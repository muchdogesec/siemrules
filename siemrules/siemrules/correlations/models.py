from datetime import date as dt_date
from enum import Enum
import itertools
from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator, root_validator
from typing import ClassVar, List, Dict, Optional
from uuid import UUID


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
        if not any(map(lambda x: x!=None, [self.eq, self.gt, self.gte, self.lt, self.lte])):
            raise ValueError("At least one of eq, gt, gte, lt, or lte must be defined in condition.")
        return self

class Correlation(BaseModel):
    type: CorrelationType = Field(..., description="Correlation type (e.g. event_count, value_count, temporal, etc.)")
    rules: Optional[List[UUID]] = Field(default=None, description="List of UUIDs referencing Sigma rules", min_length=1)
    group_by: List[str] = Field(..., alias="group-by", description="Fields to group by (e.g. User, ComputerName)")
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

    class Config:
        populate_by_name = True
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
            
        elif info.field_name not in required_fields and v:
                raise ValueError(f"'{info.field_name}' is not supported for correlation type '{correlation_type}'.")
        
        return v

class RuleModel(BaseModel):
    title: str = Field(min_length=3, description="Title of the Sigma rule")
    description: str = Field(min_length=10, description="Description of the Sigma rule")
    correlation: 'Correlation' = Field(..., description="Correlation configuration for the rule")

    author: Optional[str] = None
    date: Optional["dt_date"] = Field(default=None)
    modified: Optional["dt_date"] = None