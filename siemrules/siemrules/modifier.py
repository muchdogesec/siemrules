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
            ref for ref in indicator.get('external_references', []) if ref['source_name'] == "siemrules-created-type"
        ]
    )
    
    detection.detection_id = indicator['id'].replace('indicator--', '')
    bundler.report.external_references.clear()
    bundler.report.external_references.extend(report['external_references'])
    bundler.report.object_marking_refs.clear()
    bundler.report.object_marking_refs.extend(report['object_marking_refs'])
    container = DetectionContainer(success=True, detections=[])
    detection.modified = bundler.modified.date()
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


class DRFDetection(DRFBaseModel, ModifierDetection):
    drf_config = {"validate_pydantic": True}

    @staticmethod
    def is_valid(s, initial_data):
            unknown_keys = set(initial_data.keys()) - set(s.fields.keys())
            if unknown_keys:
                raise validators.ValidationError("Got unexpected fields: {}".format(unknown_keys))
            
    @classmethod
    def merge_detection(cls, old_detection: BaseDetection, request_data: dict):
        return {**old_detection.model_dump(exclude=['date'], exclude_unset=True, exclude_none=True), **request_data}
    
    def to_sigma_rule_detection(self):
        return SigmaRuleDetection.model_validate(self.model_dump())
    
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
        if self.author:
            self._identity = json.loads(self.author)
        return super().model_post_init(__context)
    
    def clean_author(self):
        if self.author and self._identity:
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
                tlp_level=self.tlp_level.name.replace('-', '+'),
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



def get_modification(model, input_text, old_detection: SigmaRuleDetection, prompt) -> SigmaRuleDetection:
    old_detection._bundler = SimpleNamespace(report=SimpleNamespace(created=datetime.now(), modified=datetime.now()))
    assert isinstance(old_detection, BaseDetection), "rule must be of type detection"
    detections = DetectionContainer(success=True, detections=[old_detection])
    ai_detection = LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(SigmaRuleDetection),
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

    retval = old_detection.model_copy()
    for attr in ai_detection.model_fields_set:
        setattr(retval, attr, getattr(ai_detection, attr))
    return retval

