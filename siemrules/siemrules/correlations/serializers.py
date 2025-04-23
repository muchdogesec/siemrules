from datetime import datetime, UTC
from siemrules.siemrules.serializers import validate_model
from siemrules.siemrules.utils import TLP_Levels
from .models import RuleModel as CorrelationRule, Correlation
from drf_pydantic import BaseModel as DRFBaseModel, DrfPydanticSerializer
from drf_pydantic.parse import create_serializer_from_model, SERIALIZER_REGISTRY
from rest_framework import serializers






    
class DRFCorrelationRule(DRFBaseModel, CorrelationRule):
    drf_config = {"validate_pydantic": True}
    
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
    author = serializers.CharField()
    modified = serializers.DateTimeField(default=None)
    tlp_level = serializers.ChoiceField(choices=TLP_Levels.choices, default=TLP_Levels.CLEAR, help_text='If TLP exist in rule, setting a value for this property will overwrite the existing value. When unset, the `tlp.` tag in the report will be turned into a TLP level. Defaults to `clear` if there is no `tlp.` tag in rule.')