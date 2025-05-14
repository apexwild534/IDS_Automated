from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Literal, List, Dict

class Alert(BaseModel):
    id: int | None = None
    timestamp: datetime
    severity: str
    source_ip: str | None = None
    destination_ip: str | None = None
    description: str

    class Config:
        from_attributes = True

class Condition(BaseModel):
    field: str
    operator: Literal["equals", "not_equals", "contains", "not_contains", "regex", "greater_than", "less_than"]
    value: str

class SequenceCondition(BaseModel):
    data_source: Literal["network", "logs"]
    condition: Condition

class Rule(BaseModel):
    id: int | None = None
    name: str
    description: str | None = None
    severity: str
    is_active: bool = True
    data_source: Literal["network", "logs", "both"] = "both"
    conditions: List[Condition] = []
    threshold_count: Optional[int] = None
    threshold_window: Optional[int] = None
    sequence: Optional[List[SequenceCondition]] = None
    sequence_window: Optional[int] = None

    class Config:
        from_attributes = True

class SystemStatus(BaseModel):
    overall_status: str
    data_ingestion: str
    detection_engine: str
    alert_storage: str

class NetworkPacketData(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str
    length: int
    flags: Optional[str] = None
    checksum: Optional[str] = None
    data: Optional[str] = None

class SystemLogData(BaseModel):
    timestamp: datetime
    hostname: str
    log_level: str
    source: str
    message: str
    checksum: Optional[str] = None