import logging
import textwrap
from rest_framework import viewsets, status, response


from drf_spectacular.utils import OpenApiParameter

import typing
from django.conf import settings

from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings
from .models import File

from drf_spectacular.utils import extend_schema, extend_schema_view



@extend_schema_view(
    destroy=extend_schema(
        summary="Delete all objects associated with identity",
        description=textwrap.dedent(
            """
            This endpoint will delete all Files, Reports, Rules and any other STIX objects created using this identity. It will also delete the Identity object selected.
            """
        ),
    ),
    list=extend_schema(
        summary="Search identity objects",
        description="",
    ),
)
class IdentityView(viewsets.ViewSet):
    
    SORT_PROPERTIES = [
        "created_descending",
        "created_ascending",
        "name_descending",
        "name_ascending",
    ]
    openapi_tags = ["Identities"]
    skip_list_view = True
    lookup_url_kwarg = "identity_id"
    lookup_value_regex = r'identity--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=dict(pattern=lookup_value_regex),
            description="The full STIX `id` of the Identity object. e.g. `identity--cfc24d7a-0b5e-4068-8bfc-10b66059afe0`."
        )
    ]
    @staticmethod
    def classify_objects(object_ids: list[str]):
        collections = {}
        for doc_id in object_ids:
            collection, _, key = doc_id.partition('/')
            collection_holder: list = collections.setdefault(collection, [])
            collection_holder.append(key)
        return collections

    def destroy(self, request, *args, identity_id=None, **kwargs):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        vertices = helper.execute_query('''
            FOR doc IN @@view
            FILTER doc.id == @identity_id OR doc.created_by_ref == @identity_id
            RETURN doc._id
        ''', bind_vars={"identity_id": identity_id, '@view': settings.VIEW_NAME}, paginate=False)

        objects = helper.execute_query('''
            FOR doc IN @@view
            FILTER
                    doc.id == @identity_id OR
                    doc.created_by_ref == @identity_id OR
                    doc._from IN @vertex_ids OR doc._to IN @vertex_ids
            RETURN doc._id
        ''',
            bind_vars={"identity_id": identity_id, '@view': settings.VIEW_NAME, 'vertex_ids': vertices},
            paginate=False,
        )

        logging.info(f'removing {len(objects)} objects')
        for collection, documents in self.classify_objects(objects).items():
            logging.info(f'removing {len(documents)} documents from {collection}')
            helper.execute_query(
                '''
                FOR _key IN @documents
                REMOVE {_key} IN @@collection
                RETURN NULL
                ''', paginate=False, bind_vars={'@collection': collection, 'documents': documents}
            )
        File.objects.filter(identity__id=identity_id).delete()
        return response.Response(status=status.HTTP_204_NO_CONTENT)
    
    @extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('name', description="Filter by the `name` of identity object. Search is wildcard so `co` will match `company`, `cointel`, etc."),
            OpenApiParameter('sort', description="Sort the results by selected property", enum=SORT_PROPERTIES),
        ],
    )
    def list(self, request, *args, **kwargs):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        binds = {
            "@view": settings.VIEW_NAME,
        }
        more_filters = []
        if name := helper.query.get('name'):
            binds['name'] = "%" + name.replace('%', r'\%') + "%"
            more_filters.append('FILTER doc.name LIKE @name')

        query = """
        FOR doc IN @@view
        SEARCH doc.type == "identity" AND doc._is_latest == TRUE
        #more_filters

        COLLECT id = doc.id INTO docs
        LET doc = docs[0].doc
        #sort_stmt
        LIMIT @offset, @count
        RETURN KEEP(doc, KEYS(doc, TRUE))
        """
    
        query = query.replace(
            '#sort_stmt', helper.get_sort_stmt(
                self.SORT_PROPERTIES
            )
        ).replace('#more_filters', '\n'.join(more_filters))
        return helper.execute_query(query, bind_vars=binds)