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
        summary="Upload a new File",
        description=textwrap.dedent(
            """
            Upload a file to be processed by Stixify. During processing a file is turned into markdown by [file2txt](https://github.com/muchdogesec/file2txt/), which is then passed to [txt2stix](https://github.com/muchdogesec/txt2stix/) to .

            The following key/values are accepted in the body of the request:

            * `file` (required): Full path to the file to be converted. The mimetype of the file uploaded must match that expected by the `mode` selected. This is a file2txt setting.
            * `report_id` (optional): Only pass a UUIDv4. It will be use to generate the STIX Report ID, e.g. `report--<UUID>`. If not passed, this file will be randomly generated. This is a txt2detection setting.
            * `detection_language` (required): the detection language you want the rule to be written in. This is a txt2detection setting. Options are:
                * `spl`: Splunk
                * `kql`: Sentinel
                * `elastic_dsl`: Elastic Security
                * `yara-l-2`: Chronicle
                * `sigma`: Sigma (recommended)
            * `mode` (required): How the File should be processed. This is a file2txt setting. Options are:
                * `txt`: Filetypes supported (mime-type): `txt` (`text/plain`)
                * `image`: Filetypes supported (mime-type): `jpg` (`image/jpg`), `.jpeg` (`image/jpeg`), `.png` (`image/png`), `.webp` (`image/webp`)
                * `csv`: Filetypes supported (mime-type): `csv` (`text/csv`)
                * `html`: Filetypes supported (mime-type): `html` (`text/html`)
                * `html_article`: same as `html` but only considers the article on the page, good for blog posts. Filetypes supported (mime-type): `html` (`text/html`)
                * `word`: Filetypes supported (mime-type): `docx` (`application/vnd.openxmlformats-officedocument.wordprocessingml.document`), `doc` (`application/msword`)
                * `pdf`: Filetypes supported (mime-type): `pdf` (`application/pdf`)
                * `powerpoint`: Filetypes supported (mime-type): `ppt` (`application/vnd.ms-powerpoint`), `.jpeg` (`application/vnd.openxmlformats-officedocument.presentationml.presentation`)
            * `name` (required): This will be used as the name value of the STIX Report object generated. This is a txt2detection setting.
            * `identity` (optional): This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, [the Stixify identity object will be used](https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/stixify.json). his is a txt2detection setting.
            * `tlp_level` (optional): This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting. Options are:
                    * `red`
                    * `amber+strict`
                    * `amber`
                    * `green`
                    * `clear`
            * `confidence` (optional): Will be added to the `confidence` value of the Report SDO created. A value between 0-100. `0` means confidence unknown. `1` is the lowest confidence score, `100` is the highest confidence score.
            * `labels` (optional): Will be added to the `labels` of the Report SDO created.
            * `defang` (default `true`): whether to defang the observables in the blog. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a file2txt setting.
            * `ai_provider` (default `true`):  An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.

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
        summary="Search and retrieve Jobs",
        description=textwrap.dedent(
            """
            Jobs track the status of File upload, conversion of the File into markdown and the extraction of the data from the text. For every new File added a job will be created. The `id` of a Job is printed in the POST responses, but you can use this endpoint to search for the `id` again, if required.
            """
        ),
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
        file_id = BaseInFilter(help_text="(list): search jobs by file's id")

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
            When a file has been processed, 0 or more reports will be created.

            You can use this endpoint to retrieve them.
            """
        ),
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

