from datetime import UTC, datetime
import io
from types import SimpleNamespace
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
)

from llama_index.core import PromptTemplate, ChatPromptTemplate
import textwrap
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from llama_index.core.program import LLMTextCompletionProgram
from drf_pydantic import BaseModel as DRFBaseModel
from rest_framework import serializers, validators


def modify_indicator(report, indicator: dict, detection: Detection):
    detection.detection_id = indicator['id'].replace('indicator--', '')
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
    bundler.report.external_references.clear()
    bundler.report.external_references.extend(report['external_references'])
    bundler.report.object_marking_refs.clear()
    bundler.report.object_marking_refs.extend(report['object_marking_refs'])
    bundler.bundle_detections(DetectionContainer(success=True, detections=[detection]))
    retval = []
    for obj in bundler.bundle_dict['objects']:
        if obj['id'] not in report['object_refs']:
            continue
        retval.append(obj)
        obj['object_marking_refs'] = indicator['object_marking_refs']
    return retval



class DRFDetection(DRFBaseModel, Detection):
    drf_config = {"validate_pydantic": True}
    @staticmethod
    def is_valid(s):
        if hasattr(s, 'initial_data'):
            unknown_keys = set(s.initial_data.keys()) - set(s.fields.keys())
            if unknown_keys:
                raise validators.ValidationError("Got unknown fields: {}".format(unknown_keys))

def yaml_to_detection(modification: str, indicator_types=[]):
    indicator_types = indicator_types or []
    modification = yaml.safe_load(io.StringIO(modification))
    modification.update(indicator_types=indicator_types)
    return Detection.model_validate(modification)


def get_modification(model, input_text, old_detection: Detection, prompt) -> DetectionContainer:
    old_detection._bundler = SimpleNamespace(report=SimpleNamespace(created=datetime.now(), modified=datetime.now()))
    assert isinstance(old_detection, Detection), "rule must be of type detection"
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

