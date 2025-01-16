from django.shortcuts import render

from rest_framework import viewsets, parsers, decorators, mixins
from . import models
from .import serializers
from .serializers import FileSerializer, ImageSerializer, JobSerializer
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import textwrap
import typing
from dogesec_commons.utils import Pagination, Ordering
from .md_helper import MarkdownImageReplacer, mistune
from siemrules.worker import tasks
from rest_framework.response import Response
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, NumericRangeFilter, DateTimeFilter, BaseInFilter, BaseCSVFilter


from siemrules.siemrules.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
if typing.TYPE_CHECKING:
    from siemrules import settings
from django.http import FileResponse, HttpRequest, HttpResponseNotFound
from . import arangodb_helpers

@extend_schema_view(
    create=extend_schema(
        summary="upload a new file",
        description="upload a new file",
    ),
    list=extend_schema(
        summary="list files",
        description="list files",
    ),
    destroy=extend_schema(
        summary="delete a file",
        description="delete a file",
    ),
    retrieve=extend_schema(
        summary="get a file by id",
        description="get a file by id",
    ),
    images=extend_schema(
            responses={200: ImageSerializer(many=True), 404: DEFAULT_404_ERROR, 400: DEFAULT_400_ERROR},
            filters=False,
            summary="Retrieve images found in a File",
            description=textwrap.dedent(
            """
            When [file2txt](https://github.com/muchdogesec/file2txt/) processes a file it will extract all images from the file and store them locally. You can see these images referenced in the markdown produced (see File markdown endpoint). This endpoint lists the image files found in the File selected.
            """
        ),
    ),
    markdown=extend_schema(
        responses={200:{}, 404: DEFAULT_404_ERROR},
        summary="Get the processed markdown for a File",
        description=textwrap.dedent(
            """
            Whan a file is uploaded it is converted to markdown using [file2txt](https://github.com/muchdogesec/file2txt/) which is subsequently used to make extractions from. This endpoint will return that output.
            
            This endpoint is useful for debugging issues in extractions when you think there could be an issue with the content being passed to the extractors.
            """
        ),
    ),
)
class FileView(mixins.ListModelMixin, mixins.DestroyModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    openapi_tags = ["Files"]
    pagination_class = Pagination("files")
    serializer_class = serializers.FileSerializer
    parser_classes = [parsers.MultiPartParser]
    

    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["created", "name"]
    ordering = "created_descending"

    lookup_url_kwarg = 'file_id'

    def get_queryset(self):
        return models.File.objects.all()
    

    class filterset_class(FilterSet):
        report_id = BaseInFilter(help_text="(list): search by Report ID generated from this file")
        name = CharFilter(help_text="filter by name, is wildcard")
        tlp_level = ChoiceFilter(help_text="", choices=arangodb_helpers.TLP_Levels.choices)
        created_by_ref = BaseInFilter(help_text="")
            
    @extend_schema(responses={200: serializers.JobSerializer}, request=serializers.FileSerializer)
    def create(self, request, *args, **kwargs):
        serializer = FileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        temp_file = request.FILES['file']
        file_instance = serializer.save(mimetype=temp_file.content_type)
        job_instance =  models.Job.objects.create(file=file_instance)
        job_serializer = JobSerializer(job_instance)
        tasks.new_task(job_instance, file_instance)
        return Response(job_serializer.data)
    

    @decorators.action(detail=True, methods=["GET"])
    def markdown(self, request, *args, file_id=None, **kwargs):
        obj: File = self.get_object()
        if not obj.markdown_file:
            return HttpResponseNotFound("No markdown file")
        modify_links = mistune.create_markdown(escape=False, renderer=MarkdownImageReplacer(self.request, models.FileImage.objects.filter(report__id=file_id)))
        return FileResponse(streaming_content=modify_links(obj.markdown_file.read().decode()), content_type='text/markdown', filename=f'{obj.name}-markdown.md')
    
    @decorators.action(detail=True, pagination_class=Pagination("images"))
    def images(self, request, file_id=None, image=None):
        queryset = self.get_object().images.order_by('name')
        paginator = Pagination('images')

        page = paginator.paginate_queryset(queryset, request, self)

        if page is not None:
            serializer = ImageSerializer(page, many=True, context=dict(request=request))
            return paginator.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

@extend_schema_view(
    list=extend_schema(
        summary="list jobs",
        description="list jobs",
    ),
    retrieve=extend_schema(
        summary="get a job by id",
        description="get a job by id",
    ),
)
class JobView(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    openapi_tags = ["Jobs"]
    pagination_class = Pagination("jobs")
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = 'job_id'    

    class filterset_class(FilterSet):
        file_id = BaseInFilter(help_text="(list): search jobs by file's id")

    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["run_datetime", "state"]
    ordering = "run_datetime_descending"
    def get_queryset(self):
        return models.Job.objects.all()
    
@extend_schema_view(
    list=extend_schema(
        summary="list rules",
        description="list rules",
    ),
    retrieve=extend_schema(
        summary="get a rule by indicator id",
        description="get a rule by indicator id",
    ),
)
class RuleView(viewsets.GenericViewSet):
    openapi_tags = ["Rules"]
    pagination_class = Pagination("rules")
    serializer_class = serializers.RuleSerializer
    lookup_url_kwarg = 'indicator_id'

    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=dict(pattern=r'^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'), description="The `id` of the Report. e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`.",
        )
    ]

    class filterset_class(FilterSet):
        file_id = BaseInFilter(help_text="(list): search by Report ID generated from this file")
        indicator_id = BaseInFilter(help_text="(list): search using the Indicator ID for this rule")
        name = CharFilter(help_text="filter by name, is wildcard")
        tlp_level = ChoiceFilter(help_text="", choices=arangodb_helpers.TLP_Levels.choices)
        attack_id = BaseInFilter(help_text="only show rules that reference these attack ids")
        cve_id = BaseInFilter(help_text="only show rules that reference these cve ids")
        created_by_ref = BaseInFilter(help_text="Filter the result by only the reports created by this identity. Pass in the format `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`")

    def list(self, request, *args, **kwargs):
        return arangodb_helpers.get_rules(request)
    
    def retrieve(self, request, *args, indicator_id=None, **kwargs):
        return arangodb_helpers.get_single_rule(indicator_id)

