
import uuid
from rest_framework import viewsets, decorators, status, exceptions, request, validators
from django.http import HttpRequest
from rest_framework.response import Response

from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes

import typing
from django.conf import settings

from dogesec_commons.objects.helpers import ArangoDBHelper

if typing.TYPE_CHECKING:
    from siemrules import settings

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


def fix_report_id(report_id: str):
    if report_id.startswith('report--'):
        return report_id
    return "report--"+report_id

def remove_report(report_id: str):
    helper = ArangoDBHelper(settings.VIEW_NAME, request.Request(HttpRequest()))
    report_id = fix_report_id(report_id)
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
        collections[collection].append(key)

    deletion_query = """
        FOR _key in @objects
        REMOVE {_key} IN @@collection
        RETURN _key
    """

    for collection, objects in collections.items():
        bind_vars = {
            "@collection": collection,
            "objects": objects,
        }
        helper.execute_query(deletion_query, bind_vars, paginate=False)


@extend_schema_view(
    list=extend_schema(
        summary="Search for Report objects created from Files",
        description=textwrap.dedent(
            """
            Search for Report objects created from Files
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Get a Report object using its ID",
        description=textwrap.dedent(
            """
            Get a Report object using its ID
            """
        ),
    ),
    objects=extend_schema(
        summary="Get all objects linked to a Report ID",
        description=textwrap.dedent(
            """
            This endpoint returns all STIX objects that were extracted and created for the File linked to this report.
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete all STIX objects for a Report ID",
        description=textwrap.dedent(
            """
            This endpoint will delete a Report using its ID. It will also delete all the STIX objects extracted from the Report.

            IMPORTANT: this request does NOT delete the file this Report was generated from. To delete the file, use the delete file endpoint.
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
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=dict(pattern=r'^report--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'), description="The `id` of the Report. e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`."
        )
    ]

    @extend_schema()
    def retrieve(self, request, *args, **kwargs):
        report_id = kwargs.get(self.lookup_url_kwarg)
        report_id = self.validate_report_id(report_id)
        reports: Response = ArangoDBHelper(settings.VIEW_NAME, request).get_objects_by_id(
            fix_report_id(report_id)
        )
        if not reports.data:
            raise exceptions.NotFound(
                detail=f"report object with id `{report_id}` - not found"
            )
        return reports

    @extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('identity', description="Filter the result by only the reports created by this identity. Pass in the format `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`"),
            OpenApiParameter('name', description="Filter by the `name` of a report. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('tlp_level', description="", enum=[f[0] for f in TLP_Levels.choices]),
            OpenApiParameter('description', description="Filter by the content in a report `description` (which contains the markdown version of the report). Will search for descriptions that contain the value entered. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('labels', description="searches the `labels` property for the value entered. Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."),
            OpenApiParameter('confidence_min', description="The minimum confidence score of a report `0` is no confidence, `1` is lowest, `100` is highest.", type=OpenApiTypes.NUMBER),
            OpenApiParameter('created_max', description="Maximum value of `created` value to filter by in format `YYYY-MM-DD`."),
            OpenApiParameter('created_min', description="Minimum value of `created` value to filter by in format `YYYY-MM-DD`."),
        ],
    )
    def list(self, request, *args, **kwargs):
        return self.get_reports()
    
    @extend_schema(
        responses=ArangoDBHelper.get_paginated_response_schema(),
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    )
    @decorators.action(methods=["GET"], detail=True)
    def objects(self, request, *args, report_id=..., **kwargs):
        report_id = self.validate_report_id(report_id)
        return self.get_report_objects(fix_report_id(report_id))
    
    @classmethod
    def fix_report_id(self, report_id):
        if report_id.startswith('report--'):
            return report_id
        return "report--"+report_id
    
    @classmethod
    def validate_report_id(self, report_id:str):
        if not report_id.startswith('report--'):
            raise validators.ValidationError({self.lookup_url_kwarg: f'`{report_id}`: must be a valid STIX report id'})
        report_uuid = report_id.replace('report--', '')
        try:
            uuid.UUID(report_uuid)
        except Exception as e:
            raise validators.ValidationError({self.lookup_url_kwarg: f'`{report_id}`: {e}'})
        return report_uuid

    @extend_schema()
    def destroy(self, request, *args, **kwargs):
        report_id = kwargs.get(self.lookup_url_kwarg)
        report_id = self.validate_report_id(report_id)

        File.objects.filter(id=report_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

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

        if term := helper.query.get('confidence_min'):
            if term.replace('.', '').isdigit():
                bind_vars['confidence_min'] = float(term)
                filters.append("FILTER doc.confidence >= @confidence_min")

        if term := helper.query.get('created_max'):
            bind_vars['created_max'] = term
            filters.append("FILTER doc.created <= @created_max")
        if term := helper.query.get('created_min'):
            bind_vars['created_min'] = term
            filters.append("FILTER doc.created >= @created_min")

        query = """
            FOR doc in @@collection
            FILTER doc.type == @type AND doc._is_latest
            // <other filters>
            @filters
            // </other filters>
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return helper.execute_query(query.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars)

    def get_report_objects(self, report_id):
        helper = ArangoDBHelper(settings.VIEW_NAME, self.request)
        bind_vars = {
                "@collection": settings.VIEW_NAME,
                'report_id': report_id,                
        }
        query = """
            FOR doc in @@collection
            FILTER doc._stixify_report_id == @report_id
            
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, TRUE))
        """
        return helper.execute_query(query, bind_vars=bind_vars)
    