from fastapi import FastAPI, HTTPException
from typing import List
from datetime import datetime
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData
import re

app = FastAPI()

# Dummy data (will be replaced later)
alerts_db = []  # Initialize as empty
rules_db = [
    Rule(id=1, name="SQL Injection Pattern", pattern="SELECT.*FROM.*WHERE", severity="High", is_active=True),
    Rule(id=2, name="Unusual Process", pattern="suspicious_process.exe", severity="Medium", is_active=True),
]

def process_network_data(packet: NetworkPacketData):
    print(f"Processing network data: {packet}")
    for rule in rules_db:
        if rule.is_active and (rule.data_source == "network" or rule.data_source == "both"):
            if rule.data_field:
                field_value = getattr(packet, rule.data_field, None)
                if field_value and re.search(rule.pattern, str(field_value), re.IGNORECASE):
                    alert = Alert(
                        id=len(alerts_db) + 1,
                        timestamp=packet.timestamp,
                        severity=rule.severity,
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        description=f"Network traffic matched rule: {rule.name} (Pattern: '{rule.pattern}' in field '{rule.data_field}')"
                    )
                    alerts_db.append(alert)
                    print(f"Alert generated from network: {alert}")
                    return
            elif re.search(rule.pattern, str(packet.model_dump_json()), re.IGNORECASE): # Fallback to checking all fields if data_field is not specified
                alert = Alert(
                    id=len(alerts_db) + 1,
                    timestamp=packet.timestamp,
                    severity=rule.severity,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    description=f"Network traffic matched rule (all fields): {rule.name} (Pattern: '{rule.pattern}')"
                )
                alerts_db.append(alert)
                print(f"Alert generated from network (all fields): {alert}")
                return

def process_system_log(log: SystemLogData):
    print(f"Processing system log: {log}")
    for rule in rules_db:
        if rule.is_active and (rule.data_source == "logs" or rule.data_source == "both"):
            if rule.data_field:
                field_value = getattr(log, rule.data_field, None)
                if field_value and re.search(rule.pattern, str(field_value), re.IGNORECASE):
                    alert = Alert(
                        id=len(alerts_db) + 1,
                        timestamp=log.timestamp,
                        severity=rule.severity,
                        source_ip=None,
                        destination_ip=None,
                        description=f"System log matched rule: {rule.name} (Pattern: '{rule.pattern}' in field '{rule.data_field}') - Log: {log.message}"
                    )
                    alerts_db.append(alert)
                    print(f"Alert generated from log: {alert}")
                    return
            elif re.search(rule.pattern, str(log.model_dump_json()), re.IGNORECASE): # Fallback to checking all fields if data_field is not specified
                alert = Alert(
                    id=len(alerts_db) + 1,
                    timestamp=log.timestamp,
                    severity=rule.severity,
                    source_ip=None,
                    destination_ip=None,
                    description=f"System log matched rule (all fields): {rule.name} (Pattern: '{rule.pattern}') - Log: {log.message}"
                )
                alerts_db.append(alert)
                print(f"Alert generated from log (all fields): {alert}")
                return
@app.post("/network_data")
async def receive_network_data(packet_data: NetworkPacketData):
    """Endpoint to receive network packet data from agents."""
    print(f"Received network data: {packet_data}")
    process_network_data(packet_data)
    return {"message": "Network data received and processed"}

@app.post("/system_log")
async def receive_system_log(log_data: SystemLogData):
    """Endpoint to receive system log data from agents."""
    print(f"Received system log: {log_data}")
    process_system_log(log_data)
    return {"message": "System log received successfully"}

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