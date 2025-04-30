from datetime import UTC, datetime, date as dt_date
import io
from types import SimpleNamespace
from typing import Annotated, Any, Optional
from pydantic import Field, HttpUrl, computed_field
import yaml
from txt2detection.ai_extractor.utils import (
    ParserWithLogging,
)
from txt2detection.ai_extractor import prompts
from txt2detection.bundler import Bundler
from txt2detection.utils import parse_model
from txt2detection.models import (
    Detection,
    DetectionContainer,
    BaseDetection,
    AIDetection,
    Statuses,
    SigmaTag,
    Level
)

from llama_index.core import PromptTemplate, ChatPromptTemplate
import textwrap
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from llama_index.core.program import LLMTextCompletionProgram
from drf_pydantic import BaseModel as DRFBaseModel
from rest_framework import serializers, validators


def modify_indicator(report, indicator: dict, detection: Detection):
    bundler = Bundler(
        "name",
        None,
        "red",
        "description",
        report['labels'],
        datetime(2020, 1, 1),
        report_id=report['id'].replace('report--', ''),
        modified=datetime.now(UTC)
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
        obj['object_marking_refs'] = indicator['object_marking_refs']
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
    def is_valid(s):
        if initial_data := getattr(s, 'initial_data', dict()):
            initial_data.pop('indicator_types', [])
            unknown_keys = set(initial_data.keys()) - set(s.fields.keys())
            if unknown_keys:
                raise validators.ValidationError("Got unknown fields: {}".format(unknown_keys))
            

def yaml_to_detection(modification: str, indicator_types=[]):
    indicator_types = indicator_types or []
    modification = yaml.safe_load(io.StringIO(modification))
    modification.update(indicator_types=indicator_types)
    return Detection.model_validate(modification)


def get_modification(model, input_text, old_detection: Detection, prompt) -> DetectionContainer:
    old_detection._bundler = SimpleNamespace(report=SimpleNamespace(created=datetime.now(), modified=datetime.now()))
    assert isinstance(old_detection, BaseDetection), "rule must be of type detection"
    detections = DetectionContainer(success=True, detections=[old_detection])
    return LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(DetectionContainer),
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

