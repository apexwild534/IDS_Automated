from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Literal

class Alert(BaseModel):
    id: int | None = None
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
    data_source: Literal["network", "logs", "both"] = "both" # Added data_source field

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
    flags: Optional[str] = None  # E.g., SYN, ACK, FIN
    checksum: Optional[str] = None
    data: Optional[str] = None # Added data field to match your curl request

class SystemLogData(BaseModel):
    timestamp: datetime
    hostname: str
    log_level: str
    source: str
    message: str
    checksum: Optional[str] = None