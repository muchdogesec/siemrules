
import uuid
from rest_framework import viewsets, decorators, status, exceptions, request, validators
from django.http import HttpRequest
from rest_framework.response import Response
from dogesec_commons.objects.helpers import OBJECT_TYPES

from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes

import typing
from django.conf import settings

from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings

from siemrules.siemrules import arangodb_helpers
from siemrules.siemrules.models import TLP_LEVEL_STIX_ID_MAPPING, File, TLP_Levels
from drf_spectacular.utils import extend_schema, extend_schema_view
import textwrap

from rest_framework import request
from django.http import HttpRequest
from django.conf import settings
import typing

if typing.TYPE_CHECKING:
    from .. import settings


import typing
from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings

def report_id_as_id(report_id):
    return ReportView.path_param_as_uuid(report_id).removeprefix('report--')

def can_remove_report(report_id):
    rules = arangodb_helpers.get_rules(arangodb_helpers.request_from_queries(report_id=report_id), paginate=False)
    related_correlations = arangodb_helpers.related_correlation_rules([rule['id'] for rule in rules])
    if related_correlations:
        raise validators.ValidationError(dict(message=f'sorry, you cannot delete this file/report because it is linked to {len(related_correlations)} correlation(s)', correlations=related_correlations))

def remove_report(report_id: str):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    report_id = ReportView.path_param_as_report_id(report_id)
    bind_vars = {
            "@collection": helper.collection,
            'report_id': report_id,
    }
    query = """
        FOR doc in @@collection
        FILTER doc._stixify_report_id == @report_id
        RETURN doc._id
    """
    collections: dict[str, list] = {}
    out = helper.execute_query(query, bind_vars=bind_vars, paginate=False)
    for key in out:
        collection, key = key.split('/', 2)
        collections[collection] = collections.get(collection, [])
        collections[collection].append(dict(_key=key))

    for collection, objects in collections.items():
        helper.db.collection(collection).delete_many(objects, silent=True)


@extend_schema_view(
    list=extend_schema(
        summary="Search for retrieve created Reports",
        description=textwrap.dedent(
            """
            During processing, txt2detection creates a STIX Report object to represent the file uploaded (Intel and Prompt mode). The Report object contains the text the report, and also references all the Rules (STIX Indicator Objects) created from it based on the intelligence it contains.

            You can use this endpoint to retrieve them.

            **IMPORTANT:** YML file uploads are only converted into files. No report will exist for YML uploads.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Get a Report by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to retrieve a Report using its ID.

            If you do not know the ID of the Report you can use the Search and retrieve Reports endpoint to find it.
            """
        ),
    ),
    objects=extend_schema(
        summary="Get all objects linked to a Report ID",
        description=textwrap.dedent(
            """
            This endpoint returns all STIX objects that are linked to the report. This includes the Report itself, the Rules created from it, MITRE ATT&CK, and NVD CVE objects, as well as the STIX Relationship objects that link them.
            """
        ),
    ),
)
class ReportView(viewsets.ViewSet):
    openapi_tags = ["Reports"]
    skip_list_view = True
    lookup_url_kwarg = "report_id"
    lookup_value_regex = r'report--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=dict(pattern=lookup_value_regex), description="The `id` of the Report. e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`."
        )
    ]
    SORT_PROPERTIES = [
        "created_descending",
        "created_ascending",
        "modified_descending",
        "modified_ascending",
        "name_descending",
        "name_ascending",
    ]

    @extend_schema()
    def retrieve(self, request, *args, **kwargs):
        report_id = kwargs.get(self.lookup_url_kwarg)
        return self.get_object(report_id)
    
    def get_object(self, report_id):
        report_uuid = self.path_param_as_uuid(report_id)
        report: Response = ArangoDBHelper(settings.VIEW_NAME, self.request).get_objects_by_id(
            self.path_param_as_report_id(report_id)
        )
        if not report.data:
            raise exceptions.NotFound(
                detail=f"report object with id `{report_id}` - not found"
            )
        return report

    @extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('identity', description="Filter the results by only the reports created by this identity. Pass in the format `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`"),
            OpenApiParameter('name', description="Filter by the `name` of a report. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('tlp_level', description="Filter by the TLP level of the report", enum=[f[0] for f in TLP_Levels.choices]),
            OpenApiParameter('description', description="Filter by the content in a report `description` (which contains the markdown version of the report). Will search for descriptions that contain the value entered. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('labels', description="searches the `labels` property for the value entered. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('created_max', description="Maximum value of `created` value to filter by in format `YYYY-MM-DD`."),
            OpenApiParameter('created_min', description="Minimum value of `created` value to filter by in format `YYYY-MM-DD`."),
            OpenApiParameter('visible_to', description="Only show reports that are visible to the Identity id passed. e.g. passing `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15` would only show reports created by that identity (with any TLP level) or reports created by another identity ID but only if they are marked with `TLP:CLEAR` or `TLP:GREEN`."),
            OpenApiParameter('sort', description="Sort results by property", enum=SORT_PROPERTIES),
            OpenApiParameter('indicator_id', description="Only show report that contain rule id", many=True, explode=False,),
        ],
    )
    def list(self, request, *args, **kwargs):
        return self.get_reports()
    
    @extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter(
                "types",
                many=True,
                explode=False,
                description="Filter the results by one or more STIX Object types",
                enum=OBJECT_TYPES,
            ),
            OpenApiParameter('visible_to', description="Only show reports that are visible to the Identity id passed. e.g. passing `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15` would only show reports created by that identity (with any TLP level) or reports created by another identity ID but only if they are marked with `TLP:CLEAR` or `TLP:GREEN`."),
            OpenApiParameter('ignore_embedded_sro', type=bool, description="If set to `true` all embedded SROs are removed from the response."),
        ],
    )
    @decorators.action(methods=["GET"], detail=True)
    def objects(self, request, *args, report_id=..., **kwargs):
        report_id = self.path_param_as_uuid(report_id)
        return self.get_report_objects(self.path_param_as_report_id(report_id))
    
    @classmethod
    def path_param_as_report_id(self, report_id):
        if report_id.startswith('report--'):
            return report_id
        return "report--"+report_id
    
    @classmethod
    def path_param_as_uuid(self, report_id:str, type='report'):
        type_part, _, uuid_part = report_id.partition('--')
        if type_part != 'report':
            raise validators.ValidationError({self.lookup_url_kwarg: f'`{report_id}`: must be a valid STIX report id'})
        try:
            uuid.UUID(uuid_part)
        except Exception as e:
            raise validators.ValidationError({self.lookup_url_kwarg: f'`{report_id}`: {e}'})
        return uuid_part
    
    def get_reports(self, id=None):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        filters = []
        bind_vars = {
                "@collection": helper.collection,
                "type": 'report',
        }

        if q := helper.query_as_array('identity'):
            bind_vars['identities'] = q
            filters.append('FILTER doc.created_by_ref IN @identities')

        if tlp_level := helper.query.get('tlp_level'):
            bind_vars['tlp_level_stix_id'] = TLP_LEVEL_STIX_ID_MAPPING.get(tlp_level)
            filters.append('FILTER @tlp_level_stix_id IN doc.object_marking_refs')

        if q := helper.query.get('name'):
            bind_vars['name'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.name), @name)')

        if q := helper.query.get('description'):
            bind_vars['description'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.description), @description)')

        if term := helper.query.get('labels'):
            bind_vars['labels'] = term.lower()
            filters.append("FILTER doc.labels[? ANY FILTER CONTAINS(LOWER(CURRENT), @labels)]")

        if term := helper.query.get('created_max'):
            bind_vars['created_max'] = term
            filters.append("FILTER doc.created <= @created_max")
        if term := helper.query.get('created_min'):
            bind_vars['created_min'] = term
            filters.append("FILTER doc.created >= @created_min")


        if indicator_ids := helper.query_as_array('indicator_id'):
            bind_vars['indicator_ids'] = indicator_ids
            filters.append('FILTER doc.object_refs ANY IN @indicator_ids')

        
        visible_to_filter = ''
        if q := helper.query.get('visible_to'):
            bind_vars['visible_to'] = q
            bind_vars['marking_visible_to_all'] = TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.GREEN], TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.CLEAR]
            visible_to_filter = 'FILTER doc.created_by_ref == @visible_to OR @marking_visible_to_all ANY IN doc.object_marking_refs'

        query = """
            FOR doc in @@collection
            FILTER doc.type == @type AND doc._is_latest
            // <other filters>
            @filters
            // </other filters>
            #visible_to
            #sort_statement
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        query = query.replace(
                '#sort_statement', helper.get_sort_stmt(self.SORT_PROPERTIES)
            ).replace('#visible_to', visible_to_filter)
        resp = helper.execute_query(query.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars)
        resp.data['objects'] = list(resp.data['objects'])
        return resp

    def get_report_objects(self, report_id):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        types = helper.query.get('types', "")
        filters = []
        bind_vars = {
            "@collection": settings.VIEW_NAME,
            'report_id': report_id,
            "types": list(OBJECT_TYPES.intersection(types.split(","))) if types else None,
        }

        if q := helper.query_as_bool('ignore_embedded_sro', default=False):
            filters.append('FILTER doc._is_ref != TRUE')

                
        if q := helper.query.get('visible_to'):
            bind_vars['visible_to'] = q
            bind_vars['marking_visible_to_all'] = TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.GREEN], TLP_LEVEL_STIX_ID_MAPPING[TLP_Levels.CLEAR]
            filters.append('FILTER doc.created_by_ref == @visible_to OR @marking_visible_to_all ANY IN doc.object_marking_refs')

        query = """
            FOR doc in @@collection
            FILTER doc._stixify_report_id == @report_id
            FILTER NOT @types OR doc.type IN @types
            #filters
            
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, TRUE))
        """
        query = query.replace("#filters", '\n'.join(filters))
        resp = helper.execute_query(query, bind_vars=bind_vars)
        resp.data['objects'] = list(resp.data['objects'])
        return resp
    