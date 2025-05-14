from pydantic import BaseModel
from datetime import datetime

class Alert(BaseModel):
    id: int
    timestamp: datetime
    severity: str
    source_ip: str | None = None
    destination_ip: str | None = None
    description: str