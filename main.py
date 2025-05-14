from fastapi import FastAPI
from typing import List
from datetime import datetime
from models import Alert

app = FastAPI()

# Dummy data for now (replace with database interaction later)
alerts_db = [
    Alert(id=1, timestamp=datetime.now(), severity="High", source_ip="192.168.1.100", destination_ip="10.0.0.5", description="Possible SQL Injection attempt"),
    Alert(id=2, timestamp=datetime.now(), severity="Medium", source_ip="172.16.0.20", description="Unusual process started"),
]

@app.get("/alerts", response_model=List[Alert])
async def get_alerts():
    """
    Retrieves a list of all alerts.
    """
    return alerts_db

@app.get("/")
async def root():
    return {"message": "Hello, World!"}