from sigma.backends.kusto.kusto import KustoBackend
from typing import Type
from sigma.rule import SigmaRule
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.pipelines.elasticsearch import pipelines as elastic_pipelines
from sigma.pipelines.splunk import pipelines as splunk_pipelines
from sigma.backends.splunk.splunk import SplunkBackend
from sigma.backends.elasticsearch import (
    ElastalertBackend,
    ESQLBackend,
    LuceneBackend,
    EqlBackend,
)
from sigma.conversion.base import Backend as PysigmaBackend
from sigma.exceptions import SigmaTransformationError
from rest_framework import (
    viewsets,
    decorators,
    validators,
)
from siemrules.siemrules import serializers
from rest_framework.exceptions import ParseError

from django.http import HttpResponse
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
import textwrap
import typing
from dogesec_commons.utils import Pagination
from siemrules.siemrules import arangodb_helpers
from siemrules.siemrules.utils import PlaintextRenderer


kusto_pipelines = dict(
    azure_monitor=azure_monitor_pipeline,
    microsoft_xdr=microsoft_xdr_pipeline,
    sentinel_asim=sentinel_asim_pipeline,
)
elastic_backends: dict[
    str, Type[PysigmaBackend]
] = dict(elastalert=ElastalertBackend, esql=ESQLBackend, lucene=LuceneBackend, eql=EqlBackend)


elastic_formats = ["default", "dsl_lucene", "kibana_ndjson", "eql"]
splunk_formats = ["default", "savedsearches"]
@extend_schema_view(
    convert_kusto=extend_schema(
        summary="Convert a Base Rule to a KQL query",
        description=textwrap.dedent(
            """
            This endpoint will turn a Base Rule into KQL queries.

            We use [pySigma](https://github.com/SigmaHQ/pySigma) to perform these conversions, using [this Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto).
            """
        ),
        parameters=[
            OpenApiParameter(
                "pipeline", enum=list(kusto_pipelines), description="Select the pipeline to use. [Read more about available pipelines here](https://github.com/AttackIQ/pySigma-backend-kusto?tab=readme-ov-file#-processing-pipelines)."
            ),
        ],
    ),
    convert_elasticsearch=extend_schema(
        summary="Convert a Base Rule to an Elastic query",
        description=textwrap.dedent(
            """
            This endpoint will turn a Base Rule into Elasticsearch queries.

            We use [pySigma](https://github.com/SigmaHQ/pySigma) to perform these conversions, using [this Elasticsearch backend](https://github.com/SigmaHQ/pySigma-backend-elasticsearch).
            """
        ),
        parameters=[
            OpenApiParameter(
                "pipeline", enum=list(elastic_pipelines), description="Select the pipeline to use. [Read more about available pipelines here](https://github.com/SigmaHQ/pySigma-backend-elasticsearch?tab=readme-ov-file#pysigma-elasticsearch-backend)."
            ),
            OpenApiParameter(
                "backend",
                enum=list(elastic_backends),
                description="Select the backend to use. [Read more about available backends here](https://github.com/SigmaHQ/pySigma-backend-elasticsearch?tab=readme-ov-file#pysigma-elasticsearch-backend).",
                required=True,
            ),
            OpenApiParameter(
                "output_format",
                enum=elastic_formats,
                description=textwrap.dedent("""
                    - `default`: Lucene queries.
                    - `dsl_lucene`: DSL with embedded Lucene queries.
                    - `kibana_ndjson`: Elastic Event Query Language queries.
                    - `eql`: Kibana NDJSON with Lucene queries.
                """),
            ),
        ],
    ),
    convert_splunk=extend_schema(
        summary="Convert a Base Rule to a Splunk query",
        description=textwrap.dedent(
            """
            This endpoint will turn a Base Rule into Splunk queries.

            We use [pySigma](https://github.com/SigmaHQ/pySigma) to perform these conversions, using [this Splunk backend](https://github.com/SigmaHQ/pySigma-backend-splunk).
            """
        ),
        parameters=[
            OpenApiParameter(
                "pipeline", enum=list(splunk_pipelines), description="Select the pipeline to use. [Read more about available pipelines here](https://github.com/SigmaHQ/pySigma-backend-splunk?tab=readme-ov-file#pysigma-splunk-backend)."
            ),
            OpenApiParameter(
                "output_format",
                enum=splunk_formats,
                description=textwrap.dedent("""
                    - `default`: plain Splunk queries
                    - `savedsearches`: Splunk **savedsearches.conf** format."""),
            ),
        ],
    ),
)
class ConvertRuleView(viewsets.GenericViewSet):
    rule_type = "base-rule"
    openapi_tags = ["Base Rules"]
    lookup_url_kwarg = "indicator_id"
    renderer_classes = [PlaintextRenderer]

    lookup_value_regex = (
        r"indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )

    openapi_path_params = [
        OpenApiParameter(
            lookup_url_kwarg,
            location=OpenApiParameter.PATH,
            description="The `id` of the Indicator representing the Base Rule. e.g. `indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6`. Note the UUID part of the STIX `id` used here will match the `id` in the Rule.",
        )
    ]

    def get_rule(self, indicator_id):
        rule = arangodb_helpers.get_single_rule(
            indicator_id,
            version=self.request.query_params.get("version"),
            rule_type=self.rule_type,
        )
        return rule.data["pattern"]

    def get_pipeline(self, all_pipelines):
        pipeline_name = self.request.query_params.get("pipeline")
        if not pipeline_name:
            return None
        if pipeline_name not in all_pipelines:
            raise validators.ValidationError(f"unsupported pipeline: {pipeline_name}")
        return all_pipelines[pipeline_name]()

    def get_elastic_backend(self):
        backend_name = self.request.query_params.get("backend")
        if not backend_name:
            raise validators.ValidationError(f"`backend` query is required")
        if backend_name not in elastic_backends:
            raise validators.ValidationError(
                f"unsupported elastic search backend: {backend_name}"
            )
        return elastic_backends[backend_name]
    
    def get_splunk_output_format(self):
        output_format = self.request.query_params.get("output_format") or "default"
        if output_format not in splunk_formats:
            raise validators.ValidationError(
                f"unsupported splunk output format: {output_format}"
            )
        return output_format
    
    def get_elastic_output_format(self):
        output_format = self.request.query_params.get("output_format") or "default"
        if output_format not in elastic_formats:
            raise validators.ValidationError(
                f"unsupported elastic output format: {output_format}"
            )
        return output_format

    @decorators.action(methods=["GET"], detail=True, url_path="convert/kusto")
    def convert_kusto(self, request, *args, indicator_id=None, **kwargs):
        out = self.convert(
            KustoBackend(processing_pipeline=self.get_pipeline(kusto_pipelines)),
            self.get_rule(indicator_id),
        )
        return HttpResponse(content=out, content_type="plain/text")

    @decorators.action(methods=["GET"], detail=True, url_path="convert/splunk")
    def convert_splunk(self, request, *args, indicator_id=None, **kwargs):
        out = self.convert(
            SplunkBackend(processing_pipeline=self.get_pipeline(splunk_pipelines)),
            self.get_rule(indicator_id),
            output_format=self.get_splunk_output_format(),
        )
        return HttpResponse(content=out, content_type="plain/text")

    @decorators.action(methods=["GET"], detail=True, url_path="convert/elasticsearch")
    def convert_elasticsearch(self, request, *args, indicator_id=None, **kwargs):
        backend_cls = self.get_elastic_backend()
        out = self.convert(
            backend_cls(processing_pipeline=self.get_pipeline(elastic_pipelines)),
            self.get_rule(indicator_id),
            output_format=self.get_elastic_output_format(),
        )
        return HttpResponse(content=out, content_type="plain/text")
    
    def convert(self, backend: PysigmaBackend, rule_str, **kwargs):
        rule = SigmaRule.from_yaml(rule_str)
        try:
            converted = backend.convert_rule(rule, **kwargs)[0]
            return converted
        except SigmaTransformationError as e:
            raise ParseError({"error": str(e)})
        except Exception as e:
            raise ParseError({"error": "unknown error during conversion: " + str(e)})
