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

            It will not delete any Profiles using the Identity selected. This ensures a Profile being used by other Identities is not removed. Use the Delete Profile endpoint to delete a Profile..
            """
        ),
    ),
    list=extend_schema(
        summary="Search identity objects",
        description=textwrap.dedent(
            """
            This endpoint will allow you to search for all identities that exist.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="GET identity object by STIX ID",
        description=textwrap.dedent(
            """
            This endpoint will allow you to GET an identity object by its STIX ID.
            """
        ),
    ),
)
class IdentityView(viewsets.ViewSet):
    
    SORT_PROPERTIES = [
        "created_descending",
        "created_ascending",
        "name_descending",
        "name_ascending",
    ]
    SYSTEM_IDENTITIES = [
        "identity--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
        "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
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
            helper.db.collection(collection).delete_many([dict(_key=key) for key in documents], silent=True)
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
            "system_identities": self.SYSTEM_IDENTITIES,
        }
        more_filters = []
        if name := helper.query.get('name'):
            binds['name'] = "%" + name.replace('%', r'\%') + "%"
            more_filters.append('FILTER doc.name LIKE @name')
        more_filters.append("FILTER doc.id NOT IN @system_identities")

        query = """
        FOR doc IN @@view
        SEARCH doc.type == "identity" AND doc._is_latest == TRUE
        #more_filters

        COLLECT id = doc.id INTO docs LET doc = docs[0].doc
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
        
    def retrieve(self, request, *args, identity_id=None, **kwargs):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        binds = {
            "@view": settings.VIEW_NAME,
            "identity_id": identity_id,
        }
        query = """
        FOR doc IN @@view
        SEARCH doc.type == "identity" AND doc._is_latest == TRUE AND doc.id == @identity_id
        COLLECT id = doc.id INTO docs LET doc = docs[0].doc
        LIMIT @offset, @count
        RETURN KEEP(doc, KEYS(doc, TRUE))
        """
        return helper.execute_query(query, bind_vars=binds)
