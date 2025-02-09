
from rest_framework import viewsets, parsers, decorators, mixins
from siemrules.siemrules import models, reports
from siemrules.siemrules import serializers
from siemrules.siemrules.serializers import FileSerializer, ImageSerializer, JobSerializer
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
import textwrap
import typing
from dogesec_commons.utils import Pagination, Ordering
from siemrules.siemrules.md_helper import MarkdownImageReplacer, mistune
from siemrules.worker import tasks
from rest_framework.response import Response
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, CharFilter, BaseInFilter

from siemrules.siemrules.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
if typing.TYPE_CHECKING:
    from siemrules import settings
from django.http import FileResponse, HttpResponseNotFound
from siemrules.siemrules import arangodb_helpers

@extend_schema_view(
    create=extend_schema(
        summary="Upload a new File",
        description=textwrap.dedent(
            """
            Upload a file to be processed by SIEM Rules During processing a file is turned into markdown by [file2txt](https://github.com/muchdogesec/file2txt/), which is then passed to [txt2stix](https://github.com/muchdogesec/txt2stix/) to .

            Files cannot be modified once uploaded. If you need to reprocess a file, you must upload it again.

            The response will contain the Job information, including the Job `id`. This can be used with the GET Jobs by ID endpoint to monitor the status of the Job.
            """
        ),
    ),
    list=extend_schema(
        summary="Search and retrieve a list of uploaded Files",
        description=textwrap.dedent(
            """
            This endpoint allows you to search for Files you've uploaded. This endpoint is particularly useful if you want to download the original File uploaded or find the Report object created for the uploaded File so you can retrieve the objects created for it.
            """
        ),
        responses={200: FileSerializer, 400: DEFAULT_400_ERROR}
    ),
    destroy=extend_schema(
        summary="Delete a File by ID",
        description=textwrap.dedent(
            """
            This endpoint will delete a File using its ID. It will also delete the markdown, images and original file stored for this File.

            IMPORTANT: this request does NOT delete the Report SDO created from the file, or any other STIX objects created from this file during extractions. To delete these, use the delete report endpoint.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Get a File by ID",
        description=textwrap.dedent(
            """
            This endpoint will return information for a specific File using its ID.
            """
        ),
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
            When a file is uploaded it is converted to markdown using [file2txt](https://github.com/muchdogesec/file2txt/) which is subsequently used to make extractions from. This endpoint will return that output.
            
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
        report_id = BaseInFilter(method='filter_report_id', help_text="Filter the results by the STIX Report ID generated for this File. Pass the full STIX ID, e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`.")
        name = CharFilter(help_text="Filter by the name of the File (entered on input). Search is wildcard so `exploit` will match `exploited`, `exploits`, etc.")
        tlp_level = ChoiceFilter(help_text="Filter the files by the TLP level selected at input.", choices=models.TLP_Levels.choices)
        created_by_ref = BaseInFilter('identity__id', help_text="Filter the result by only the Files created by this identity. Pass the full STIX ID of the Identity object, e.g. `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`.")
        
        def filter_report_id(self, qs, field_name, value: str):
            file_id = [reports.report_id_as_id(v) for v in value]
            return qs.filter(pk__in=file_id)
            
    @extend_schema(responses={200: serializers.JobSerializer, 400: DEFAULT_400_ERROR}, request=serializers.FileSerializer)
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
        summary="Search and retrieve Jobs",
        description=textwrap.dedent(
            """
            Jobs track the status of File upload, conversion of the File into markdown and the extraction of the data from the text. For every new File added a job will be created. The `id` of a Job is printed in the POST responses, but you can use this endpoint to search for the `id` again, if required.
            """
        ),
        responses={200: JobSerializer, 400: DEFAULT_400_ERROR}
    ),
    retrieve=extend_schema(
        summary="Get a Job by ID",
        description=textwrap.dedent(
            """
            Using a Job ID you can retrieve information about its state via this endpoint. This is useful to see if a Job is still processing, if an error has occurred (and at what stage), or if it has completed.
            """
        ),
    ),
)
class JobView(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    openapi_tags = ["Jobs"]
    pagination_class = Pagination("jobs")
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = 'job_id'    

    class filterset_class(FilterSet):
        file_id = BaseInFilter(help_text="Filter the result by the ID of the File the Job was created from, e.g. `2632fd7a-ae33-4d35-9652-425e488c97af`.")
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["run_datetime", "state"]
    ordering = "run_datetime_descending"
    def get_queryset(self):
        return models.Job.objects.all()
    
@extend_schema_view(
    list=extend_schema(
        summary="Search and retrieve created Rules",
        description=textwrap.dedent(
            """
            During processing, txt2detection identifies detection rules from the intelligence described in the content. Each rule identified is converted into a STIX 2.1 Indicator object containing the rule.

            You can use this endpoint to retrieve them.
            """
        ),
        responses={200: serializers.RuleSerializer, 400: DEFAULT_400_ERROR}
    ),
    retrieve=extend_schema(
        summary="Get a Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to retrieve a rule using its STIX Indicator ID.

            If you do not know the ID of the Rule you can use the Search and retrieve created Rules endpoint.
            """
        ),
        responses={200: serializers.RuleSerializer(many=True)}
    ),
)
class RuleView(viewsets.GenericViewSet):
    openapi_tags = ["Rules"]
    pagination_class = Pagination("rules")
    serializer_class = serializers.RuleSerializer
    lookup_url_kwarg = 'indicator_id'

    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg, location=OpenApiParameter.PATH, type=dict(pattern=r'^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'), description="The `id` of the Indicator. e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`.",
        )
    ]

    class filterset_class(FilterSet):
        file_id = BaseInFilter(help_text="Filter the result by the ID of the File, e.g. `2632fd7a-ae33-4d35-9652-425e488c97af`.")
        indicator_id = BaseInFilter(help_text="Filter the result by the ID of the Rule. Pass the full STIX ID of the Indicator object, e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`.")
        name = CharFilter(help_text="Filter by the name of the Rule (automatically created by the AI). Search is wildcard so `exploit` will match `exploited`, `exploits`, etc.")
        tlp_level = ChoiceFilter(help_text="Filter the Rules by the TLP level of the File they were generated from.", choices=models.TLP_Levels.choices)
        attack_id = BaseInFilter(help_text="Filter the results return rules linked to a particular ATT&CK Technique. Pass the full ATT&CK ID, e.g. `T1047`.")
        cve_id = BaseInFilter(help_text="Filter the results return rules linked to a particular CVE. Pass the full CVE ID, e.g. `CVE-2024-28374`.")
        created_by_ref = BaseInFilter(help_text="Filter the result by only the reports created by this identity. Pass the full STIX ID of the Identity object, e.g. `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`.")


    def list(self, request, *args, **kwargs):
        return arangodb_helpers.get_rules(request)
    
    def retrieve(self, request, *args, indicator_id=None, **kwargs):
        return arangodb_helpers.get_single_rule(indicator_id)

