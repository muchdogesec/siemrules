from datetime import datetime
import io
import logging
import typing
import uuid

from django.conf import settings

from siemrules.siemrules.correlations.prompts import (
    CORRELATION_MODIFICATION_PROMPT,
    CORRELATION_RULES_PROMPT,
)
from siemrules.siemrules.correlations.utils import make_identity

if typing.TYPE_CHECKING:
    from siemrules import settings
from siemrules.siemrules.correlations.models import AIRuleModel, RuleModel
from siemrules.siemrules.models import default_identity
from stix2 import Identity, parse as parse_stix, Relationship
import yaml

from llama_index.core import ChatPromptTemplate
from txt2detection.ai_extractor import BaseAIExtractor

from siemrules.siemrules.correlations.models import RuleModel
from llama_index.core.program import LLMTextCompletionProgram
from txt2detection.ai_extractor.utils import (
    ParserWithLogging,
)


def make_rule(rule: RuleModel, other_documents: list[dict], id):
    rule_dict = rule.model_dump(mode="json", exclude_none=True, by_alias=True)
    rule_dict.update(id=id)
    rule_str = yaml.safe_dump_all(
        [rule_dict, *other_documents],
        indent=4,
        sort_keys=False,
    )
    return rule_str


def add_rule_indicator(
    rule: RuleModel,
    base_rule_indicators=None,
    job_data=None,
):
    job_data = job_data or dict()
    base_rule_indicators = base_rule_indicators or []
    identity = default_identity()
    # if rule_ids := rule.correlation.rules:
    #     assert len(rule_ids) == len(base_rule_indicators or []), "base rules not passed"
    if rule.author:
        # assumes rule.author must be pre-fetched identity
        identity = parse_stix(rule.author)
    elif job_data and job_data.get("identity"):
        identity = job_data["identity"]

    rule.author = identity["id"]
    job_correlation_id = job_data and job_data.get("correlation_id")
    rule.rule_id = rule.rule_id or job_correlation_id or str(uuid.uuid4())
    rule_str = make_rule(
        rule, rules_from_indicators(base_rule_indicators), rule.rule_id
    )

    ext_refs = [
    ]
    for ref in getattr(rule, "references", None) or []:
        ext_refs.append(
            dict(source_name="siemrules", description="siemrules-references", url=ref)
        )

    correlation_indicator = {
        "type": "indicator",
        "id": "indicator--" + rule.rule_id,
        "spec_version": "2.1",
        "created_by_ref": identity["id"],
        "created": job_data.get("created", rule.date),
        "modified": job_data.get("modified", rule.modified or rule.date),
        "description": rule.description,
        "indicator_types": [],
        "name": rule.title,
        "labels": [],
        "pattern_type": "sigma",
        "pattern": rule_str,
        "object_marking_refs": [
            rule.tlp_level.value["id"],
            "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb",
        ],
        "external_references": ext_refs,
        "x_sigma_type": "correlation",
        "x_sigma_level": rule.level,
        "x_sigma_status": rule.status,
        "x_sigma_falsepositives": rule.falsepositives,
    }
    correlation_indicator["valid_from"] = correlation_indicator["created"]

    logging.debug(f"===== rule {rule.rule_id} =====")
    logging.debug("```yaml\n" + str(correlation_indicator["pattern"]) + "\n```")
    logging.debug(f" =================== end of rule =================== ")

    correlation_indicator = parse_stix(correlation_indicator, allow_custom=True)
    objects = [correlation_indicator, identity, rule.tlp_level.value]
    for related_indicator in base_rule_indicators:
        objects.append(
            dict(
                type="relationship",
                spec_version="2.1",
                id="relationship--"
                + str(
                    uuid.uuid5(
                        uuid.UUID("97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"),
                        f"{correlation_indicator.id}+{related_indicator['id']}",
                    )
                ),
                created_by_ref=correlation_indicator.created_by_ref,
                created=correlation_indicator.created,
                modified=correlation_indicator.modified,
                relationship_type="contains-rule",
                description=f"{correlation_indicator.name} contains the rule {related_indicator['name']}",
                source_ref=correlation_indicator.id,
                target_ref=related_indicator["id"],
                object_marking_refs=correlation_indicator.object_marking_refs,
                _to=related_indicator["_id"],
            )
        )
    return objects


def rules_from_indicators(indicators: list[dict]):
    return [
        yaml.safe_load(io.StringIO(indicator["pattern"])) for indicator in indicators
    ]


def generate_correlation_with_ai(
    model: BaseAIExtractor, user_prompt, related_indicators
) -> AIRuleModel:
    return LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(AIRuleModel),
        prompt=ChatPromptTemplate(CORRELATION_RULES_PROMPT),
        verbose=True,
        llm=model.llm,
    )(
        rules=rules_from_indicators(related_indicators),
        user_prompt=user_prompt,
    )


def get_modification(model, input_text, old_detection: RuleModel, prompt) -> RuleModel:
    # old_detection._bundler = SimpleNamespace(report=SimpleNamespace(created=datetime.now(), modified=datetime.now()))
    assert isinstance(old_detection, RuleModel), "rule must be of type detection"
    return LLMTextCompletionProgram.from_defaults(
        output_parser=ParserWithLogging(RuleModel),
        prompt=ChatPromptTemplate(CORRELATION_MODIFICATION_PROMPT),
        verbose=True,
        llm=model.llm,
    )(
        document=input_text,
        old_rule=old_detection.model_dump(mode="json", exclude=["date", "modified"]),
        correction_prompt=prompt,
    )


def yaml_to_rule(modification: str):
    modification, *others = list(yaml.safe_load_all(io.StringIO(modification)))
    return RuleModel.model_validate(modification), others
