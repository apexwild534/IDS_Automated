from pydantic import BaseModel
from datetime import datetime

class Alert(BaseModel):
    id: int
    timestamp: datetime
    severity: str
    source_ip: str | None = None
    destination_ip: str | None = None
    description: str

class Rule(BaseModel):
    id: int | None = None
    name: str
    description: str | None = None
    pattern: str  # The pattern or signature to look for
    severity: str
    is_active: bool = True

class SystemStatus(BaseModel):
    overall_status: str
    data_ingestion: str
    detection_engine: str
    alert_storage: str