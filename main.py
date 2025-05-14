import re
from fastapi import FastAPI, HTTPException
from typing import List
from datetime import datetime
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData

app = FastAPI()

alerts_db = []
rules_db = [
    Rule(id=1, name="SQL Injection Pattern", pattern="SELECT.*FROM.*WHERE", severity="High", is_active=True, data_source="network", data_field="data", match_type="regex"),
    Rule(id=2, name="Unusual Process", pattern="suspicious_process.exe", severity="Medium", is_active=True, data_source="logs", data_field="message", match_type="substring"),
    Rule(id=3, name="Specific IP", pattern="192.168.1.100", severity="Low", is_active=True, data_source="network", data_field="source_ip", match_type="exact"),
]

def check_rule_match(rule: Rule, data_value: str | None) -> bool:
    if data_value is None:
        return False

    if rule.match_type == "exact":
        return rule.pattern == data_value
    elif rule.match_type == "substring":
        return rule.pattern in data_value
    elif rule.match_type == "regex":
        return re.search(rule.pattern, data_value, re.IGNORECASE)
    return False

def process_network_data(packet: NetworkPacketData):
    print(f"Processing network data: {packet}")
    for rule in rules_db:
        if rule.is_active and (rule.data_source == "network" or rule.data_source == "both"):
            data_value = getattr(packet, rule.data_field, None) if rule.data_field else str(packet.model_dump_json())
            if check_rule_match(rule, data_value):
                alert = Alert(
                    id=len(alerts_db) + 1,
                    timestamp=packet.timestamp,
                    severity=rule.severity,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    description=f"Network traffic matched rule: {rule.name} (Pattern: '{rule.pattern}' in field '{rule.data_field if rule.data_field else 'all fields'}', Match Type: {rule.match_type})"
                )
                alerts_db.append(alert)
                print(f"Alert generated from network: {alert}")
                return

def process_system_log(log: SystemLogData):
    print(f"Processing system log: {log}")
    for rule in rules_db:
        if rule.is_active and (rule.data_source == "logs" or rule.data_source == "both"):
            data_value = getattr(log, rule.data_field, None) if rule.data_field else str(log.model_dump_json())
            if check_rule_match(rule, data_value):
                alert = Alert(
                    id=len(alerts_db) + 1,
                    timestamp=log.timestamp,
                    severity=rule.severity,
                    source_ip=None,
                    destination_ip=None,
                    description=f"System log matched rule: {rule.name} (Pattern: '{rule.pattern}' in field '{rule.data_field if rule.data_field else 'all fields'}', Match Type: {rule.match_type}) - Log: {log.message}"
                )
                alerts_db.append(alert)
                print(f"Alert generated from log: {alert}")
                return

@app.post("/network_data")
async def receive_network_data(packet_data: NetworkPacketData):
    print(f"Received network data: {packet_data}")
    process_network_data(packet_data)
    return {"message": "Network data received and processed"}

@app.post("/system_log")
async def receive_system_log(log_data: SystemLogData):
    print(f"Received system log: {log_data}")
    process_system_log(log_data)
    return {"message": "System log received successfully"}

@app.get("/alerts", response_model=List[Alert])
async def get_alerts():
    return alerts_db

@app.get("/rules", response_model=List[Rule])
async def get_rules():
    return rules_db

@app.post("/rules", response_model=Rule, status_code=201)
async def create_rule(rule: Rule):
    rule.id = len(rules_db) + 1
    rules_db.append(rule)
    return rule

@app.get("/rules/{rule_id}", response_model=Rule)
async def get_rule(rule_id: int):
    for rule in rules_db:
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@app.put("/rules/{rule_id}", response_model=Rule)
async def update_rule(rule_id: int, updated_rule: Rule):
    for index, rule in enumerate(rules_db):
        if rule.id == rule_id:
            updated_rule.id = rule_id
            rules_db[index] = updated_rule
            return updated_rule
    raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")

@app.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int):
    for index, rule in enumerate(rules_db):
        if rule.id == rule_id:
            del rules_db[index]
            return {"detail": f"Rule with ID {rule_id} deleted"}
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