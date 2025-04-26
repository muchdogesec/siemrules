from datetime import UTC, datetime
import io
from rest_framework import (
    viewsets,
    parsers,
    decorators,
    mixins,
    renderers,
    exceptions,
    serializers as drf_serializers,
    status,
    validators,
)
from txt2detection.utils import parse_model
import yaml
from siemrules.siemrules import correlations, models, reports
from siemrules.siemrules import serializers
from siemrules.siemrules.correlations.serializers import CorrelationRuleSerializer, DRFCorrelationRule
from siemrules.siemrules.modifier import (
    DRFDetection,
    get_modification,
    modify_indicator,
    yaml_to_detection,
)
from siemrules.siemrules.serializers import (
    CorrelationJobSerializer,
    FileSerializer,
    ImageSerializer,
    JobSerializer,
)
from rest_framework.exceptions import NotFound, ParseError

from rest_framework import request
from django.http import HttpRequest, HttpResponse
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
import textwrap
import typing
from dogesec_commons.utils import Pagination, Ordering
from siemrules.siemrules.md_helper import MarkdownImageReplacer, mistune
from siemrules.siemrules.utils import SigmaRuleParser, SigmaRuleRenderer
from siemrules.worker import tasks
from rest_framework.response import Response
from django_filters.rest_framework import (
    FilterSet,
    DjangoFilterBackend,
    ChoiceFilter,
    CharFilter,
    BaseInFilter,
)

from siemrules.siemrules.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR

if typing.TYPE_CHECKING:
    from siemrules import settings
from django.http import FileResponse, HttpResponseNotFound
from siemrules.siemrules import arangodb_helpers

from drf_spectacular.views import SpectacularAPIView
from rest_framework.response import Response

class SchemaViewCached(SpectacularAPIView):
    _schema = None
    
    def _get_schema_response(self, request):
        version = self.api_version or request.version or self._get_version_parameter(request)
        if not self.__class__._schema:
            generator = self.generator_class(urlconf=self.urlconf, api_version=version, patterns=self.patterns)
            self.__class__._schema = generator.get_schema(request=request, public=self.serve_public)
        return Response(
            data=self.__class__._schema,
            headers={"Content-Disposition": f'inline; filename="{self._get_filename(request, version)}"'}
        )

@extend_schema_view(
    upload=extend_schema(
        summary="Upload an intelligence report to convert into Sigma Rules",
        description=textwrap.dedent(
            """
            Upload a file to be processed by SIEM Rules During processing a file is turned into markdown by [file2txt](https://github.com/muchdogesec/file2txt/), which is then passed to [txt2detection](https://github.com/muchdogesec/txt2detection/) to turn into rules.

            Files cannot be modified once uploaded. If you need to reprocess a file, you must upload it again.

            The response will contain the Job information, including the Job `id`. This can be used with the GET Jobs by ID endpoint to monitor the status of the Job.
            """
        ),
    ),
    sigma=extend_schema(
        summary="Upload an existing Sigma Rule",
        description=textwrap.dedent(
            """
            Upload a Sigma Rule yaml file to be processed by SIEM Rules, this file is passed as is to [txt2detection](https://github.com/muchdogesec/txt2detection/) to turn into rules.

            Files cannot be modified once uploaded. If you need to reprocess a file, you must upload it again.

            The response will contain the Job information, including the Job `id`. This can be used with the GET Jobs by ID endpoint to monitor the status of the Job.
            """
        ),
    ),
    text=extend_schema(
        summary="Enter a text input to convert into Sigma Rules",
        description=textwrap.dedent(
            """
            Create a file from a text input. During processing the created file is passed to [txt2detection](https://github.com/muchdogesec/txt2detection/) to turn into rules.

            Files cannot be modified once created from an input. If you need to reprocess a file, you must enter it again.

            The following key / values are accepted in the body of the request:

            * `text_input` (required): this is a string of text that will be passed to the AI to create the rule.
            * `name` (required): This will be assigned to the File and Report object created. Note, the names of each detection rule generated will be automatic. Max 256 characters. This is a txt2detection setting.
            * `ai_provider` (required): An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.
            * `report_id` (optional): Only pass a UUIDv4. It will be use to generate the STIX Report ID, e.g. `report--<UUID>`. If not passed, this value will be randomly generated for this file. This is a txt2detection setting.
            * `identity` (optional): This will be used as the `created_by_ref` for all created SDOs and SROs. This is a full STIX Identity JSON. e.g. `{"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"}`. If no value is passed, the Stixify identity object will be used. This is a txt2detection setting.
            * `tlp_level` (optional): This will be assigned to all SDOs and SROs created. Stixify uses TLPv2. This is a txt2detection setting.
            * `labels` (optional): Will be added to the `labels` of the Report and Indicator SDOs created, and `tags` in the Sigma rule itself.
            * `defang` (optional): Whether to defang the observables in the text. e.g. turns `1.1.1[.]1` to `1.1.1.1` for extraction. This is a file2txt setting.
            * `ignore_embedded_relationships` (optional, default: `false`): boolean, if `true` passed, this will stop ANY embedded relationships from being generated. This applies for all object types (SDO, SCO, SRO, SMO). If you want to target certain object types see `ignore_embedded_relationships_sro` and `ignore_embedded_relationships_sro` flags. This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional, default: false): boolean, if true passed, will stop any embedded relationships from being generated from SRO objects (type = `relationship`). This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional, default: false): boolean, if true passed, will stop any embedded relationships from being generated from SMO objects (type = `marking-definition`, `extension-definition`, `language-content`). This is a stix2arango setting.

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
        responses={200: FileSerializer, 400: DEFAULT_400_ERROR},
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
        responses={
            200: ImageSerializer(many=True),
            404: DEFAULT_404_ERROR,
            400: DEFAULT_400_ERROR,
        },
        filters=False,
        summary="Retrieve images found in a File",
        description=textwrap.dedent(
            """
            When [file2txt](https://github.com/muchdogesec/file2txt/) processes a file it will extract all images from the file and store them locally. You can see these images referenced in the markdown produced (see File markdown endpoint). This endpoint lists the image files found in the File selected.
            """
        ),
    ),
    markdown=extend_schema(
        responses={200: {}, 404: DEFAULT_404_ERROR},
        summary="Get the processed markdown for a File",
        description=textwrap.dedent(
            """
            When a file is uploaded it is converted to markdown using [file2txt](https://github.com/muchdogesec/file2txt/) which is subsequently used to make extractions from. This endpoint will return that output.
            
            This endpoint is useful for debugging issues in extractions when you think there could be an issue with the content being passed to the extractors.
            """
        ),
    ),
)
class FileView(
    mixins.ListModelMixin,
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    openapi_tags = ["Files"]
    pagination_class = Pagination("files")
    serializer_class = serializers.FileSerializer
    parser_classes = [parsers.MultiPartParser]

    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["created", "name"]
    ordering = "created_descending"

    lookup_url_kwarg = "file_id"

    def get_queryset(self):
        return models.File.objects.all()

    class filterset_class(FilterSet):
        report_id = BaseInFilter(
            method="filter_report_id",
            help_text="Filter the results by the STIX Report ID generated for this File. Pass the full STIX ID, e.g. `report--3fa85f64-5717-4562-b3fc-2c963f66afa6`.",
        )
        name = CharFilter(
            help_text="Filter by the name of the File (entered on input). Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."
        )
        tlp_level = ChoiceFilter(
            help_text="Filter the files by the TLP level selected at input.",
            choices=models.TLP_Levels.choices,
        )
        created_by_ref = BaseInFilter(
            "identity__id",
            help_text="Filter the result by only the Files created by this identity. Pass the full STIX ID of the Identity object, e.g. `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`.",
        )

        def filter_report_id(self, qs, field_name, value: str):
            file_id = [reports.report_id_as_id(v) for v in value]
            return qs.filter(pk__in=file_id)

    @extend_schema(
        responses={200: serializers.JobSerializer, 400: DEFAULT_400_ERROR},
        request=serializers.FileSerializer,
    )
    @decorators.action(methods=["POST"], detail=False)
    def upload(self, request, *args, **kwargs):
        serializer = FileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        temp_file = request.FILES["file"]
        file_instance = serializer.save(mimetype=temp_file.content_type)
        job_instance = models.Job.objects.create(file=file_instance, type=models.JobType.FILE)
        job_serializer = JobSerializer(job_instance)
        tasks.new_task(job_instance)
        return Response(job_serializer.data)

    @extend_schema(
        responses={200: serializers.JobSerializer, 400: DEFAULT_400_ERROR},
        request=serializers.FileSigmaSerializer,
    )
    @decorators.action(methods=["POST"], detail=False)
    def sigma(self, request, *args, **kwargs):
        serializer = serializers.FileSigmaSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        temp_file = request.FILES["sigma_file"]
        if temp_file.content_type != "application/x-yaml":
            validators.ValidationError("file content-type must be application/x-yaml")
        file_instance = serializer.save(mimetype=temp_file.content_type)
        job_instance = models.Job.objects.create(file=file_instance)
        job_serializer = JobSerializer(job_instance)
        tasks.new_task(job_instance)
        return Response(job_serializer.data)

    @extend_schema(
        responses={200: serializers.JobSerializer, 400: DEFAULT_400_ERROR},
        request=serializers.FilePromptSerializer,
    )
    @decorators.action(
        methods=["POST"], detail=False, parser_classes=[parsers.JSONParser]
    )
    def text(self, request, *args, **kwargs):
        serializer = serializers.FilePromptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_instance = serializer.save(mimetype="text/plain")
        job_instance = models.Job.objects.create(file=file_instance)
        job_serializer = JobSerializer(job_instance)
        tasks.new_task(job_instance)
        return Response(job_serializer.data)

    @decorators.action(detail=True, methods=["GET"])
    def markdown(self, request, *args, file_id=None, **kwargs):
        obj: File = self.get_object()
        if not obj.markdown_file:
            return HttpResponseNotFound("No markdown file")
        modify_links = mistune.create_markdown(
            escape=False,
            renderer=MarkdownImageReplacer(
                self.request, models.FileImage.objects.filter(report__id=file_id)
            ),
        )
        return FileResponse(
            streaming_content=modify_links(obj.markdown_file.read().decode()),
            content_type="text/markdown",
            filename=f"{obj.name}-markdown.md",
        )

    @decorators.action(detail=True, pagination_class=Pagination("images"))
    def images(self, request, file_id=None, image=None):
        queryset = self.get_object().images.order_by("name")
        paginator = Pagination("images")

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
        responses={200: JobSerializer, 400: DEFAULT_400_ERROR},
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
class JobView(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    openapi_tags = ["Jobs"]
    pagination_class = Pagination("jobs")
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = "job_id"

    class filterset_class(FilterSet):
        file_id = BaseInFilter(
            help_text="Filter the result by the ID of the File the Job was created from, e.g. `2632fd7a-ae33-4d35-9652-425e488c97af`."
        )

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
        responses={200: serializers.RuleSerializer, 400: DEFAULT_400_ERROR},
    ),
    retrieve=extend_schema(
        summary="Get a Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to retrieve a rule using its STIX Indicator ID.

            If you do not know the ID of the Rule you can use the Search and retrieve created Rules endpoint.
            """
        ),
        responses={
            200: serializers.RuleSerializer,
            (200, "application/sigma+yaml"): serializers.RuleSigmaSerializer,
        },
        parameters=[
            OpenApiParameter(
                "version",
                description="The version of the rule you want to retrieve (e.g. `2025-04-04T06:12:59.482478Z`). The `version` value is the same as the STIX objects `modified` time. You can see all of the versions of a rule using the version endpoint. ",
            )
        ],
    ),
    destroy=extend_schema(
        summary="Delete a Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to delete a Rule. All versions of the Rule that exist will be removed.

            This endpoint will remove the Rule from the databases, and any references to it (e.g. in its corresponding `report` object). However, the original `report` object the rule was created from will still remain.

            If you wish to delete the `report` object and all `indicators` (rules) connected to it, use the Delete Reports endpoint.
            """
        ),
    ),
)
class RuleView(viewsets.GenericViewSet):
    openapi_tags = ["Base Rules"]
    pagination_class = Pagination("rules")
    serializer_class = serializers.RuleSerializer
    lookup_url_kwarg = "indicator_id"

    lookup_value_regex = r'indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    rule_type = "base"

    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg,
            location=OpenApiParameter.PATH,
            # type=dict(
            #     # pattern=lookup_value_regex,
            #     type='str',
            #     format='path',
            # ),
            description="The `id` of the Indicator. e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`.",
        )
    ]

    class filterset_class(FilterSet):
        file_id = BaseInFilter(
            help_text="Filter the result by the ID of the File, e.g. `2632fd7a-ae33-4d35-9652-425e488c97af`."
        )
        indicator_id = BaseInFilter(
            help_text="Filter the result by the ID of the Rule. Pass the full STIX ID of the Indicator object, e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`."
        )
        name = CharFilter(
            help_text="Filter by the name of the Rule (automatically created by the AI). Search is wildcard so `exploit` will match `exploited`, `exploits`, etc."
        )
        tlp_level = ChoiceFilter(
            help_text="Filter the Rules by the TLP level of the File they were generated from.",
            choices=models.TLP_Levels.choices,
        )
        attack_id = BaseInFilter(
            help_text="Filter the results return rules linked to a particular ATT&CK Technique. Pass the full ATT&CK ID, e.g. `T1047`."
        )
        cve_id = BaseInFilter(
            help_text="Filter the results return rules linked to a particular CVE. Pass the full CVE ID, e.g. `CVE-2024-28374`."
        )
        created_by_ref = BaseInFilter(
            help_text="Filter the result by only the reports created by this identity. Pass the full STIX ID of the Identity object, e.g. `identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15`."
        )
        sort = ChoiceFilter(
            help_text="Sort by value",
            choices=[(f, f) for f in arangodb_helpers.RULES_SORT_FIELDS],
        )

    def get_renderers(self):
        if self.action == "retrieve":
            return [renderers.JSONRenderer(), SigmaRuleRenderer()]
        return super().get_renderers()

    def get_parsers(self):
        if getattr(self, "action", "") == "modify":
            return [SigmaRuleParser()]
        return super().get_parsers()

    def list(self, request, *args, **kwargs):
        return arangodb_helpers.get_rules(request, rule_type=self.rule_type)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "format",
                description="The format of the report, either `sigma` (returns only the Sigma YAML) or `json` (returns the STIX 2.1 Indicator object containing the Sigma rule). Make sure to set the `Accept` header correctly.",
                enum=["sigma", "json"],
            )
        ]
    )
    def retrieve(self, request, *args, indicator_id=None, **kwargs):
        return arangodb_helpers.get_single_rule(
            indicator_id, version=request.query_params.get("version"),
            rule_type=self.rule_type,
        )

    @extend_schema(
        summary="Get Versions of a Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to retrieve all versions of a rule using its STIX Indicator ID.

            If you do not know the ID of the Rule you can use the Search and retrieve created Rules endpoint.

            You can use the list of versions on the Get Rule endpoint to see each version of the Rule.
            """
        ),
        responses={
            200: {"type": "array", "items": {"type": "string", "format": "date-time"}}
        },
    )
    @decorators.action(methods=["GET"], detail=True, pagination_class=None)
    def versions(self, request, *args, indicator_id=None, **kwargs):
        return arangodb_helpers.get_single_rule_versions(
            indicator_id,
            rule_type=self.rule_type,
                                                         )

    @extend_schema(
        request=DRFDetection.drf_serializer,
        summary="Manually edit a Sigma Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to modify a Sigma Rule.

            You should only enter the parts of the Sigma Rule you wish to change. Any properties/values not passed will remain unchanged in the rule. To delete a value from a property, pass the property without the value.

            You cannot change the following properties:

            * `id`
            * `date`
            * `modified`
            * `author`


            The rule will be validated against the Sigma specification. [You can read the specification here to see available properties and values allowed](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

            You will recieve an error if validation fails. If any part of the validation fails the rule will not be updated.
            """
        ),
    )
    @decorators.action(methods=["POST"], detail=True, parser_classes=[SigmaRuleParser])
    def modify(self, request, *args, indicator_id=None, **kwargs):
        report, indicator, all_objs = arangodb_helpers.get_objects_by_id(indicator_id)

        if not report:
            raise ParseError(f"cannot find report associated with rule `{indicator_id}`")
        
        old_detection = yaml_to_detection(
            indicator["pattern"], indicator["indicator_types"]
        )
        data = {**old_detection.model_dump(exclude=['created', 'modified', 'date']), **request.data}
        s = DRFDetection.drf_serializer(data=data)
        s.is_valid(raise_exception=True)
        DRFDetection.is_valid(s)
        detection = DRFDetection.model_validate(s.data)

        return self.modify_resp(request, indicator_id, report, indicator, detection)

    def modify_resp(self, request, indicator_id, report, indicator, detection):
        new_objects = modify_indicator(report, indicator, detection)
        file_id = report["id"].removeprefix("report--")
        print(file_id, report["id"])
        arangodb_helpers.modify_rule(
            indicator["id"],
            indicator["modified"],
            new_objects[0]["modified"],
            new_objects,
        )

        return self.retrieve(request, indicator_id=indicator_id)
    
    @extend_schema(request=serializers.AIModifySerializer,
        summary="Use AI to modify a rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to get AI to modify a Sigma Rule via a prompt.

            The following key / values are accepted in the body of the request:

            * `prompt` (required): The prompt you wish to send to the AI with instructions on how to modify or improve the rule. For example; Add MITRE ATT&CK Technique T1134 to this rule.
            * `ai_provider` (required): An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.
            """
        ),
    )
    @decorators.action(methods=['POST'], detail=True)
    def modify_ai(self, request, *args, indicator_id=None, **kwargs):
        report, indicator, all_objs = arangodb_helpers.get_objects_by_id(indicator_id)
        s = serializers.AIModifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        old_detection = yaml_to_detection(
            indicator["pattern"], indicator["indicator_types"]
        )
        input_text = report["description"]
        input_text = "<SKIPPED INPUT>"
        detection_container = get_modification(
            parse_model(s.data["ai_provider"]),
            input_text,
            old_detection,
            s.data["prompt"],
        )
        if not detection_container.success:
            raise exceptions.ParseError("txt2detection: failed to execute")

        return self.modify_resp(
            request, indicator_id, report, indicator, detection_container.detections[0]
        )
    
    @extend_schema(request=serializers.RuleRevertSerializer,
        summary="Revert rule to older version",
        description=textwrap.dedent(
            """
            This endpoint allows you to roll back (revert) the content of a Base Rule to an old version more easily.

            The `version` value in the body is the STIX Indicators `modified` time for the version of the Base Rule you want to revert to.

            Note, this will not delete this version of the rule. It will create a new version with the content of the rule at the point you want to revert to, except for `modified` times, which will match the time of revert.
            """
        ),
    )
    @decorators.action(methods=['PATCH'], detail=True)
    def revert(self, request, *args, indicator_id=None, **kwargs):
        s = serializers.RuleRevertSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        rev = arangodb_helpers.delete_rule(indicator_id, rule_type=self.rule_type, rule_date=s.initial_data['version'], delete=False)
        return self.retrieve(request, indicator_id=indicator_id)

    def destroy(self, request, *args, indicator_id=None, **kwargs):
        arangodb_helpers.delete_rule(indicator_id, 
            rule_type=self.rule_type,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        summary="Get objects linked to Sigma Rule",
        description=textwrap.dedent(
            """
            description here
            """
        ),
        responses=arangodb_helpers.ArangoDBHelper.get_paginated_response_schema(),
        parameters=arangodb_helpers.ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('version', description="The version of the rule to use in retrieval.",)
        ],
    )
    @decorators.action(methods=["GET"], detail=True)
    def objects(self, request, *args, indicator_id=None, **kwargs):
        return arangodb_helpers.get_objects_for_rule(
            indicator_id, version=request.query_params.get("version"),
            rule_type=self.rule_type,
        )
    


@extend_schema_view(
    upload=extend_schema(summary="create correlation from yml file", description="create new correlation from sigma"),
    from_prompt=extend_schema(summary="create correlation from prompts", description="create new correlation from prompt"),
    list=extend_schema(summary="search correlation rules", description="search correlation rules"),
    retrieve=extend_schema(summary="get a correlation rule by id", description="sget a correlation rule by id"),
    objects=extend_schema(summary="get a correlation rule objects", description="sget a correlation rule by id"),
    versions=extend_schema(summary="get a correlation rule versions", description="sget a correlation rule by id"),
)
class CorrelationView(RuleView):
    openapi_tags = ["Correlation Rules"]
    rule_type = "correlation"

    class filterset_class(RuleView.filterset_class):
        cve_id = None
        attack_id = None
        file_id = None
        base_rule = BaseInFilter(
            help_text="Filter the result by the ID of contained base rules. Pass the full STIX ID of the Indicator object, e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`."
        )

    def get_renderers(self):
        if self.action == "retrieve":
            return [renderers.JSONRenderer(), SigmaRuleRenderer()]
        return super().get_renderers()

    def get_parsers(self):
        if self.request and "/upload/" in self.request.path:
            return [SigmaRuleParser()]
        return super().get_parsers()

    def get_rules(self, rule_ids):
        r = request.Request(HttpRequest())
        rule_ids = [str(r) for r in rule_ids]
        indicator_ids = ["indicator--" + rule_id for rule_id in rule_ids]
        r.query_params.update(indicator_id=",".join(indicator_ids))
        indicators = arangodb_helpers.get_rules(r, paginate=False, nokeep=False)
        rules = {
            indicator["id"].replace("indicator--", "")
            for indicator in indicators
        }
        if non_existent_rules := set(rule_ids).difference(rules):
            raise validators.ValidationError(
                f"non existent rules in correlation {non_existent_rules}"
            )
        return indicators

    @extend_schema(request=DRFCorrelationRule.drf_serializer)
    @decorators.action(methods=['POST'], detail=False, serializer_class=JobSerializer)
    def upload(self, request, *args, **kwargs):
        rule_s = DRFCorrelationRule.drf_serializer(data=request.data)
        rule_s.is_valid(raise_exception=True)
        rule = DRFCorrelationRule.model_validate(rule_s.data)
        related_indicators = []
        if rule.correlation.rules:
            related_indicators = self.get_rules(rule.correlation.rules)

        job_instance = models.Job.objects.create(type=models.JobType.CORRELATION, data=dict(input_form='sigma'))
        job_s = CorrelationJobSerializer(job_instance)

        tasks.new_correlation_task(job_instance, rule, related_indicators, {})
        return Response(job_s.data)
    

    @extend_schema(request=CorrelationRuleSerializer)
    @decorators.action(methods=['POST'], detail=False, serializer_class=JobSerializer)
    def from_prompt(self, request, *args, **kwargs):
        s = CorrelationRuleSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        related_indicators = []
        if s.validated_data['rules']:
            related_indicators = self.get_rules(s.validated_data['rules'])

        job_instance = models.Job.objects.create(type=models.JobType.CORRELATION, data=dict(input_form='ai_prompt', **s.data))
        job_s = CorrelationJobSerializer(job_instance)
        tasks.new_correlation_task(job_instance, s.validated_data, related_indicators, s.validated_data)
        return Response(job_s.data)
    
    modify = None
    modify_ai = None


    @extend_schema(
        request=correlations.serializers.DRFCorrelationRuleModify.drf_serializer,
        summary="Manually edit a Correlation Rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to modify a Correlation Rule.

            You should only enter the parts of the Correlation Rule you wish to change. Any properties/values not passed will remain unchanged in the rule. To delete a value from a property, pass the property without the value.

            You cannot change the following properties:

            * `id`
            * `date`
            * `modified`
            * `author`
            
            """
        ),
    )
    @decorators.action(methods=["POST"], detail=True, parser_classes=[SigmaRuleParser])
    def modify(self, request, *args, indicator_id=None, **kwargs):
        report, indicator, all_objs = arangodb_helpers.get_objects_by_id(indicator_id)
        old_rule = correlations.correlations.yaml_to_rule(
            indicator["pattern"]
        )
        print(f"{old_rule=}")
        new_rule = correlations.serializers.DRFCorrelationRuleModify.serialize_rule_from(old_rule, request.data)
        print(new_rule)

        return self.modify_resp(request, indicator_id, report, indicator, new_rule)

    def modify_resp(self, request, indicator_id, report, indicator, rule):
        new_objects = correlations.correlations.add_rule_indicator(rule, [], indicator['labels'][0].split('.')[-1], dict(modified=datetime.now(UTC)))
        arangodb_helpers.modify_rule(
            indicator["id"],
            indicator["modified"],
            new_objects[0]["modified"],
            new_objects,
        )

        return self.retrieve(request, indicator_id=indicator_id)
    
    @extend_schema(request=serializers.AIModifySerializer,
        summary="Use AI to modify a rule by ID",
        description=textwrap.dedent(
            """
            Use this endpoint to get AI to modify a Sigma Rule via a prompt.

            The following key / values are accepted in the body of the request:

            * `prompt` (required): The prompt you wish to send to the AI with instructions on how to modify or improve the rule. For example; Add MITRE ATT&CK Technique T1134 to this rule.
            * `ai_provider` (required): An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.
            """
        ),
    )
    @decorators.action(methods=['POST'], detail=True)
    def modify_ai(self, request, *args, indicator_id=None, **kwargs):
        report, indicator, all_objs = arangodb_helpers.get_objects_by_id(indicator_id)
        s = serializers.AIModifySerializer(data=request.data)
        s.is_valid(raise_exception=True)
        old_detection = yaml_to_detection(
            indicator["pattern"], indicator["indicator_types"]
        )
        input_text = report["description"]
        input_text = "<SKIPPED INPUT>"
        detection_container = get_modification(
            parse_model(s.data["ai_provider"]),
            input_text,
            old_detection,
            s.data["prompt"],
        )
        if not detection_container.success:
            raise exceptions.ParseError("txt2detection: failed to execute")

        return self.modify_resp(
            request, indicator_id, report, indicator, detection_container.detections[0]
        )