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
    combined_string = f"{packet.source_ip} {packet.destination_ip} {packet.protocol} {packet.source_port} {packet.destination_port} {packet.flags} {packet.length} {packet.checksum} {packet.timestamp} {getattr(packet, 'data', '')}"
    print(f"String being checked: {combined_string}")
    for rule in rules_db:
        if rule.is_active and re.search(rule.pattern, combined_string, re.IGNORECASE):
            alert = Alert(
                id=len(alerts_db) + 1,
                timestamp=packet.timestamp,
                severity=rule.severity,
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                description=f"Network traffic matched rule: {rule.name} (Pattern: {rule.pattern})"
            )
            alerts_db.append(alert)
            print(f"Alert generated: {alert}")
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
    # We'll implement log processing later
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