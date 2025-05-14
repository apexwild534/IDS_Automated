from fastapi import FastAPI, HTTPException
from typing import List
from datetime import datetime
from models import Alert, Rule, SystemStatus

app = FastAPI()

# Dummy data for alerts (replace with database later)
alerts_db = [
    Alert(id=1, timestamp=datetime.now(), severity="High", source_ip="192.168.1.100", destination_ip="10.0.0.5", description="Possible SQL Injection attempt"),
    Alert(id=2, timestamp=datetime.now(), severity="Medium", source_ip="172.16.0.20", description="Unusual process started"),
]

# Dummy data for rules (replace with database later)
rules_db = [
    Rule(id=1, name="SQL Injection Pattern", pattern="SELECT.*FROM.*WHERE", severity="High", is_active=True),
    Rule(id=2, name="Unusual Process", pattern="suspicious_process.exe", severity="Medium", is_active=True),
]

@app.get("/alerts", response_model=List[Alert])
async def get_alerts():
    """Retrieves a list of all alerts."""
    return alerts_db

@app.get("/rules", response_model=List[Rule])
async def get_rules():
    """Retrieves a list of all detection rules."""
    return rules_db

@app.post("/rules", response_model=Rule, status_code=201)
async def create_rule(rule: Rule):
    """Creates a new detection rule."""
    rule.id = len(rules_db) + 1  # Simple in-memory ID generation
    rules_db.append(rule)
    return rule

@app.get("/rules/{rule_id}", response_model=Rule)
async def get_rule(rule_id: int):
    """Retrieves a specific detection rule by ID."""
    for rule in rules_db:
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@app.put("/rules/{rule_id}", response_model=Rule)
async def update_rule(rule_id: int, updated_rule: Rule):
    """Updates an existing detection rule."""
    for index, rule in enumerate(rules_db):
        if rule.id == rule_id:
            updated_rule.id = rule_id  # Ensure ID matches
            rules_db[index] = updated_rule
            return updated_rule
    raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@app.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int):
    """Deletes a detection rule by ID."""
    for index, rule in enumerate(rules_db):
        if rule.id == rule_id:
            del rules_db[index]
            return {"detail": f"Rule with ID {rule_id} deleted"}
    raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@app.get("/status", response_model=SystemStatus)
async def get_status():
    """Retrieves the current status of the SentinelAI system."""
    # In a real application, you would check the status of each component
    status_data = SystemStatus(
        overall_status="OK",
        data_ingestion="Running",
        detection_engine="Active",
        alert_storage="Connected"
    )
    return status_data


@app.get("/")
async def root():
    return {"message": "Hello, World!"}