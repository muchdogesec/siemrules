from datetime import UTC, date as dt_date, datetime
from enum import Enum
import itertools
import json
import uuid
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator, NameEmail
from typing import ClassVar, List, Dict, Optional
from uuid import UUID
from pydantic_core import Url
from txt2detection.models import SigmaTag, BaseDetection, TLP_LEVEL, Statuses, Level, tlp_from_tags, set_tlp_level_in_tags
import stix2

from siemrules.siemrules.correlations.utils import validate_author


class CorrelationType(str, Enum):
    event_count = "event_count"
    value_count = "value_count"
    temporal = "temporal"
    temporal_ordered = "temporal_ordered"

class Condition(BaseModel):
    eq: Optional[int] = None
    gt: Optional[int] = None
    gte: Optional[int] = None
    lt: Optional[int] = None
    lte: Optional[int] = None

    @model_validator(mode="after")
    def validate_condition_operators(self) -> "Condition":
        if all(map(lambda x: x==None, [self.eq, self.gt, self.gte, self.lt, self.lte])):
            raise ValueError("At least one of eq, gt, gte, lt, or lte must be defined in condition.")
        return self

class Correlation(BaseModel):
    type: CorrelationType = Field(..., description="Correlation type (e.g. event_count, value_count, temporal, etc.)")
    rules: Optional[List[UUID]] = Field(default=None, description="List of UUIDs referencing Sigma rules", min_length=1)
    group_by: Optional[List[str]] = Field(..., alias="group-by", description="Fields to group by (e.g. User, ComputerName)", examples=["User", "ComputerName"])
    timespan: str = Field(..., description="Timespan like '10s', '5m', '2h', '1d'")
    condition: Optional[Condition] = Field(default=None, description="Condition to match correlated events")
    field: Optional[str] = Field(
        default=None,
        description="Field to count distinct values (required only for value_count)"
    )
    aliases: Optional[Dict[str, Dict[str, str]]] = Field(
        default=None,
        description="Optional field name aliases across rule names (e.g. {\"rule1\": {\"User\": \"Username\"}})"
    )

    FIELD_REQUIREMENT_MAPPING: ClassVar = {
        CorrelationType.event_count: ["group_by", "timespan", "condition"],
        CorrelationType.value_count: ["group_by", "timespan", "condition", "field"],
        CorrelationType.temporal: ["rules", "group_by", "timespan"],
        CorrelationType.temporal_ordered: ["rules", "group_by", "timespan"],
    }
    FIELD_REQUIREMENT_FIELDS: ClassVar = set(itertools.chain(*FIELD_REQUIREMENT_MAPPING.values()))

    model_config = ConfigDict(
        populate_by_name = True,
        json_schema_extra = {
            "examples": [
                {
                    "type": "value_count",
                    "rules": ["0e95725d-7320-415d-80f7-004da920fc11"],
                    "group-by": ["ComputerName", "WorkstationName"],
                    "field": "User",
                    "timespan": "1d",
                    "condition": {
                        "gte": 100
                    }
                }
            ]
        }
    )

    @field_validator("timespan", mode='after')
    @classmethod
    def validate_timespan(cls, v):
        if not isinstance(v, str) or not v[:-1].isdigit() or v[-1] not in "smhd":
            raise ValueError("Timespan must be in format '<number><s/m/h/d>', e.g. '10m', '1h'.")
        return v

    @field_validator(*FIELD_REQUIREMENT_FIELDS, mode='after')
    def validate_required_fields_by_type(cls, v, info: ValidationInfo):
        correlation_type = info.data.get('type')
        
        # Get the list of required fields for the given correlation type
        required_fields = cls.FIELD_REQUIREMENT_MAPPING.get(correlation_type, [])

        # Check that all required fields are present
        if info.field_name in required_fields and not v:
                raise ValueError(f"'{info.field_name}' is required for correlation type '{correlation_type}'.")
        return v
    

class BaseRuleModel(BaseModel):
    title: str = Field(min_length=3, description="Title of the Sigma rule")
    description: str = Field(min_length=10, description="Description of the Sigma rule")
    correlation: 'Correlation' = Field(..., description="Correlation configuration for the rule")
    falsepositives: Optional[list[str]] = Field(description="False positives", default=None)
    status: Optional[Statuses] = None
    level: Optional[Level] = None

class RuleModelExtraProperties(BaseModel):
    references : Optional[list[str]] = None
    related: Optional[list[dict]] = None
    

class RuleModel(BaseRuleModel, RuleModelExtraProperties):
    author: Optional[str] = None
    date: Optional["dt_date"] = Field(default_factory=lambda: datetime.now(UTC).date())
    modified: Optional["dt_date"] = None
    tags: Optional[list[SigmaTag]] = Field(default_factory=list)

    _rule_id = None

    @field_validator('date', 'modified', mode='before')
    @classmethod
    def clean_dates(cls, value):
        if isinstance(value, datetime):
            return value.date()
        return value
    
    @field_validator('tags', mode='after')
    @classmethod
    def validate_tlp(cls, tags: list[str]):
        tlps = []
        for tag in tags:
            if tag.startswith('tlp.'):
                tlps.append(tag)
        if len(tlps) != 1:
            raise ValueError(f'tag must contain exactly one tag in tlp namespace. Got {tlps}')
        return tags
    
    @property
    def tlp_level(self):
        return tlp_from_tags(self.tags)
    
    @tlp_level.setter
    def tlp_level(self, level):
        return set_tlp_level_in_tags(self.tags, level)
    
    @property
    def rule_id(self):
        return self._rule_id
    
    @rule_id.setter
    def rule_id(self, rule_id):
        self._rule_id = str(rule_id)

    @field_validator('author', mode='before')
    @classmethod
    def validate_author(cls, author):
        return validate_author(author)



class AIRuleModel(BaseRuleModel):
    pass