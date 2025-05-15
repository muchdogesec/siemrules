from datetime import UTC, datetime, date as dt_date
import io
import json
from types import SimpleNamespace
from typing import Optional
import jsonschema.exceptions
from pydantic import Field, HttpUrl, computed_field, field_validator
import yaml
from txt2detection.ai_extractor.utils import (
    ParserWithLogging,
)
from django.template.defaultfilters import slugify
from django.core.files.uploadedfile import SimpleUploadedFile
from txt2detection.ai_extractor import prompts
from txt2detection.bundler import Bundler
from txt2detection.models import (
    DetectionContainer,
    BaseDetection,
    SigmaRuleDetection,
    Statuses,
    SigmaTag,
    Level
)

from llama_index.core import ChatPromptTemplate
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from llama_index.core.program import LLMTextCompletionProgram
from drf_pydantic import BaseModel as DRFBaseModel
from rest_framework import validators
from txt2detection.models import SigmaTag, BaseDetection, Statuses, Level, tlp_from_tags, set_tlp_level_in_tags


def modify_indicator(report, indicator: dict, detection: BaseDetection):
    bundler = Bundler(
        "name",
        None,
        "red",
        "description",
        report.get('labels', []),
        datetime(2020, 1, 1),
        report_id=report['id'].replace('report--', ''),
        modified=datetime.now(UTC),
        external_refs=[
            ref for ref in indicator.get('external_references', []) if ref['source_name'] == "siemrules-type"
        ]
    )
    
    detection.detection_id = indicator['id'].replace('indicator--', '')
    bundler.report.external_references.clear()
    bundler.report.external_references.extend(report['external_references'])
    bundler.report.object_marking_refs.clear()
    bundler.report.object_marking_refs.extend(report['object_marking_refs'])
    container = DetectionContainer(success=True, detections=[])
    container.detections.append(detection)
    bundler.bundle.objects.clear() # remove any default object
    bundler.bundle_detections(container)
    retval = []
    for obj in bundler.bundle_dict['objects']:
        retval.append(obj)
    return retval


class ModifierDetection(BaseDetection):
    title: str
    description: Optional[str] = None
    status: Optional[Statuses] = None
    level: Optional[Level] = None
    tags: list[SigmaTag]
    license: Optional[str] = None
    falsepositives: Optional[list[str]] = None
    references: Optional[list[HttpUrl]] = None
    logsource: dict = None
    detection: dict

    @computed_field(alias="date")
    @property
    def date(self) -> dt_date:
        return self._bundler.report.created.date()

    @computed_field
    @property
    def modified(self) -> dt_date:
        return self._bundler.report.modified.date()


class DRFDetection(DRFBaseModel, ModifierDetection):
    drf_config = {"validate_pydantic": True}

    @staticmethod
    def is_valid(s, initial_data):
            unknown_keys = set(initial_data.keys()) - set(s.fields.keys())
            if unknown_keys:
                raise validators.ValidationError("Got unknown fields: {}".format(unknown_keys))
            
    @classmethod
    def merge_detection(cls, old_detection: BaseDetection, request_data: dict):
        for k in ['tags', 'falsepositives', 'references']:
            v = request_data.pop(k, [])
            if v != None:
                request_data.update({k: [*getattr(old_detection, k, []), *v]})
        return {**old_detection.model_dump(exclude=['created', 'modified', 'date'], exclude_unset=True, exclude_none=True), **request_data}
    
class DRFSigmaRule(DRFBaseModel, SigmaRuleDetection):
    drf_config = {"validate_pydantic": True}
    _identity: dict = None
    tags: list[SigmaTag] = Field(default_factory=list)

    @staticmethod
    def is_valid(s, initial_data):
        unknown_keys = set(initial_data.keys()) - set(s.fields.keys())
        if unknown_keys:
            raise validators.ValidationError("Got unknown fields: {}".format(unknown_keys))
        
    @field_validator('author', mode='before')
    @classmethod
    def validate_author(cls, author):
        from siemrules.siemrules.correlations.utils import validate_author
        return validate_author(author)
    
    def model_post_init(self, __context):
        self._identity = json.loads(self.author)
        return super().model_post_init(__context)
    
    def clean_author(self):
        self.author = self._identity['id']
    
    def to_file_serializer(self, request_body):
        try:
            self.clean_author()
            rule = self.make_rule(None)
        except jsonschema.exceptions.ValidationError as e:
            raise validators.ValidationError(f'validation with schema failed: {e.json_path}: {e.message}')
        from siemrules.siemrules.serializers import FileSigmaYamlSerializer
        data = dict(
                name=self.title,
                identity=self._identity,
                sigma_file=SimpleUploadedFile(f"{slugify(self.title)}.yml", content=bytes(rule, 'utf-8'), content_type="application/sigma+yaml"),
            )

        s = FileSigmaYamlSerializer(
            data=data
        )
        s.is_valid(raise_exception=True)
        return s
    
    @field_validator("tags", mode="before")
    @classmethod
    def add_default_tlp(cls, tags):
        try:
            tlp_level = tlp_from_tags(tags)
            if not tlp_level:
                set_tlp_level_in_tags(tags, "clear")
            return tags
        except Exception as e:
            raise ValueError(e)
            

def yaml_to_detection(modification: str, indicator_types=[]):
    indicator_types = indicator_types or []
    modification = yaml.safe_load(io.StringIO(modification))
    modification.update(indicator_types=indicator_types)
    return SigmaRuleDetection.model_validate(modification)

class ModifierDetectionContainer(DetectionContainer):
    detections: SigmaRuleDetection


def get_modification(model, input_text, old_detection: SigmaRuleDetection, prompt) -> DetectionContainer:
    old_detection._bundler = SimpleNamespace(report=SimpleNamespace(created=datetime.now(), modified=datetime.now()))
    assert isinstance(old_detection, BaseDetection), "rule must be of type detection"
    detections = DetectionContainer(success=True, detections=[old_detection])
    return LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(ModifierDetectionContainer),
        prompt=ChatPromptTemplate(prompts.SIEMRULES_PROMPT.message_templates
        + [
            ChatMessage.from_str("{old_rule}", MessageRole.ASSISTANT),
            ChatMessage.from_str(
                "Please answer in the specified format.\n{correction_prompt}",
                MessageRole.USER,
            ),
        ]),
        verbose=True,
        llm=model.llm,
    )(
        document=input_text,
        old_rule=detections.model_dump(mode='json', exclude=['date', 'modified']),
        correction_prompt=prompt,
    )

