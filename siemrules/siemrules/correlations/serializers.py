from .models import RuleModel as CorrelationRule
from drf_pydantic import BaseModel as DRFBaseModel

class DRFCorrelationRule(DRFBaseModel, CorrelationRule):
    drf_config = {"validate_pydantic": True}
    