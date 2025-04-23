from datetime import datetime, UTC
from siemrules.siemrules.serializers import validate_model
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