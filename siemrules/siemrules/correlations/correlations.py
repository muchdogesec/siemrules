from datetime import datetime
import logging
import typing
import uuid

from django.conf import settings

from siemrules.siemrules.correlations.prompts import CORRELATION_RULES_PROMPT
if typing.TYPE_CHECKING:
    from siemrules import settings
from siemrules.siemrules.correlations.models import AIRuleModel, RuleModel
from siemrules.siemrules.models import default_identity
from stix2 import Identity, parse as parse_stix
import yaml

from llama_index.core import ChatPromptTemplate
from txt2detection.ai_extractor import BaseAIExtractor

from siemrules.siemrules.correlations.models import RuleModel
from llama_index.core.program import LLMTextCompletionProgram
from txt2detection.ai_extractor.utils import (
    ParserWithLogging,
)


def create_indicator(correlation: RuleModel):
    pass

def make_identity(name):
    return Identity(id='identity--'+str(uuid.uuid5(settings.STIX_NAMESPACE, f"txt2detection+{name}")), name=name, created_by_ref=default_identity()['id'], created=datetime(2020, 1, 1), modified=datetime(2020, 1, 1))

def add_rule_indicator(rule: RuleModel, extra_documents = None, correlation_rule_type='manual', job_data=None):
    job_data = job_data or dict()
    extra_documents = extra_documents or []
    identity = default_identity()
    if rule.author:
        identity = make_identity(rule.author)
    indicator_id = str(uuid.uuid4())
    rule_str = yaml.safe_dump_all(
        [rule.model_dump(mode='json', exclude_none=True), *extra_documents],
        indent=4,
        sort_keys=False,
    )
    indicator = {
        "type": "indicator",
        "id": "indicator--"+indicator_id,
        "spec_version": "2.1",
        "created_by_ref": identity["id"],
        "created": job_data.get('created', rule.date),
        "modified": job_data.get('modified', rule.modified or rule.date),
        "indicator_types": [],
        "name": rule.title,
        "labels": [f"siemrules.correlation-rule.{correlation_rule_type}"],
        "pattern_type": 'sigma',
        "pattern": rule_str,
        "valid_from": rule.date,
        "object_marking_refs": [

        ],
        # "external_references": self.url_refs + [dict(source_name="txt2detection-status", external_id=self.indicator_status)],
    }
    
    logging.debug(f"===== rule {indicator_id} =====")
    logging.debug("```yaml\n"+str(indicator['pattern'])+"\n```")
    logging.debug(f" =================== end of rule =================== ")
        
    indicator = parse_stix(indicator, allow_custom=True)
    return [identity, indicator]


def generate_correlation_with_ai(model: BaseAIExtractor, user_prompt, rules) -> AIRuleModel:
    print(model, type(model))
    return LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(AIRuleModel),
        prompt=ChatPromptTemplate(CORRELATION_RULES_PROMPT),
        verbose=True,
        llm=model.llm,
    )(
        rules=rules,
        user_prompt=user_prompt,
    )