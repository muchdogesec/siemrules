from datetime import datetime
import io
import yaml
from txt2detection.ai_extractor.utils import (
    Detection,
    DetectionContainer,
    ParserWithLogging,
)
from txt2detection.ai_extractor import prompts
from txt2detection.bundler import Bundler
from txt2detection.utils import parse_model

from llama_index.core import PromptTemplate, ChatPromptTemplate
import textwrap
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from llama_index.core.program import LLMTextCompletionProgram
from drf_pydantic import BaseModel as DRFBaseModel


def modify_indicator(report, indicator: dict, detection: Detection):
    bundler = Bundler(
        "name", None, "red", "description", 10, ["some new label"], datetime(2020, 1, 1), report_id=report['id'].replace('report--', '')
    )
    bundler.report.external_references.clear()
    bundler.report.external_references.extend(report['external_references'])
    detection.id = indicator['id']
    bundler.bundle_detections(DetectionContainer(success=True, detections=[detection]))
    # return bundler.bundle_dict
    return [obj for obj in bundler.bundle_dict['objects'] if obj['id'] in report['object_refs']]



class DRFDetection(DRFBaseModel, Detection):
    pass

def yaml_to_detection(modification: str, indicator_types=[]):
    modification = yaml.safe_load(io.StringIO(modification))
    modification.update(indicator_types=indicator_types)
    return Detection.model_validate(modification)


def get_modification(model, input_text, old_detection, prompt) -> DetectionContainer:
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
        old_rule=detections.model_dump_json(),
        correction_prompt=prompt,
    )

