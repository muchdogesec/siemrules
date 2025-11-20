import copy
from datetime import datetime, UTC
import json

import jsonschema
from siemrules.siemrules import models
from siemrules.siemrules.serializers import STIXIdentityField, validate_model
from siemrules.siemrules.utils import TLP_Levels
from .models import RuleModel as CorrelationRule, Correlation, BaseRuleModel, RuleModelExtraProperties, set_tlp_level_in_tags, tlp_from_tags
from drf_pydantic import BaseModel as DRFBaseModel, DrfPydanticSerializer
from drf_pydantic.parse import create_serializer_from_model, SERIALIZER_REGISTRY
from rest_framework import serializers
from rest_framework import validators

from typing import Optional
from pydantic import Field, field_validator
from txt2detection.models import SigmaTag


from django.template.defaultfilters import slugify
from django.core.files.uploadedfile import SimpleUploadedFile



    
class DRFCorrelationRule(DRFBaseModel, CorrelationRule):
    drf_config = {"validate_pydantic": True}

    @field_validator("tags", mode="before")
    @classmethod
    def add_default_tlp(cls, tags):
        try:
            tlp_level = tlp_from_tags(tags)
            if not tlp_level:
                set_tlp_level_in_tags(tags, TLP_Levels.CLEAR.value)
            return tags
        except Exception as e:
            raise ValueError(e)
        


def to_file_serializer(rule: CorrelationRule, request_body):
    self = rule
    _identity = models.default_identity()
    if self.author:
        _identity = json.loads(self.author)

    from siemrules.siemrules.serializers import FileSigmaYamlSerializer
    data = dict(
        name=rule.title,
        identity=_identity,
        sigma_file=SimpleUploadedFile(
            f"correlation-{slugify(rule.title)}.yml",
            content=request_body,
            content_type="application/sigma+yaml",
        ),
        type=models.VersionRuleType.CORRELATION_RULE,
        tlp_level=rule.tlp_level.name.replace("-", "+"),
    )

    s = FileSigmaYamlSerializer(data=data)
    s.is_valid(raise_exception=True)
    return s

def default_tags_factory():
    return ['tlp.clear']

class DRFCorrelationRuleModify(DRFBaseModel, BaseRuleModel, RuleModelExtraProperties):
    tags: Optional[list[SigmaTag]] = Field(default_factory=default_tags_factory)
    drf_config = {"validate_pydantic": True}

    @staticmethod
    def is_valid(s):
        if hasattr(s, 'initial_data'):
            unknown_keys = set(s.initial_data.keys()) - set(s.fields.keys())
            if unknown_keys:
                raise validators.ValidationError("Got unknown fields: {}".format(unknown_keys))
            
    @classmethod
    def serialize_rule_from(cls, old_rule: CorrelationRule, data: dict):
        data = cls.merge_detection(old_rule, data)
        tlp_level = tlp_from_tags(old_rule.tags)
        set_tlp_level_in_tags(data['tags'], tlp_level.name)
        s = cls.drf_serializer(data=data)
        s.is_valid(raise_exception=True)
        cls.is_valid(s)
        new_rule = CorrelationRule.model_validate({**s.data, **dict(date=old_rule.date, modified=datetime.now(UTC))})
        return new_rule

    @classmethod
    def merge_detection(cls, old_detection: CorrelationRule, request_data: dict):
        return {**old_detection.model_dump(exclude=['created', 'modified', 'date', 'author'], exclude_unset=True, exclude_none=True, by_alias=True), **request_data}

    
# class _CorrelationPatch(create_serializer_from_model(Correlation, {"validate_pydantic": True})):
fields_getter = SERIALIZER_REGISTRY[Correlation].get_fields
def patch_fields(self):
    fields = fields_getter(self)
    fields['group-by'] = fields['group_by']
    return fields

SERIALIZER_REGISTRY[Correlation].get_fields = patch_fields


class CorrelationRuleSerializer(serializers.Serializer):
    rules = serializers.ListField(child=serializers.UUIDField())
    prompt = serializers.CharField()
    ai_provider = serializers.CharField(required=True, validators=[validate_model], help_text="An AI provider and model to be used for rule generation in format `provider:model` e.g. `openai:gpt-4o`. This is a txt2detection setting.")
    created = serializers.DateTimeField(default=lambda: datetime.now(UTC))
    identity = STIXIdentityField(required=False)
    modified = serializers.DateTimeField(default=None)
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.CLEAR, help_text='If TLP exist in rule, setting a value for this property will overwrite the existing value. When unset, the `tlp.` tag in the report will be turned into a TLP level. Defaults to `clear` if there is no `tlp.` tag in rule.')


