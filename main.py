from fastapi import FastAPI, HTTPException, Depends
from typing import List
from datetime import datetime
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData
import re
from database import engine, Base, SessionLocal, AlertDB, RuleDB  # Import RuleDB here
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

def process_network_data(packet: NetworkPacketData, db: Session = Depends(get_db)):
    print(f"Processing network data: {packet}")
    for rule in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["network", "both"])).all():
        rule_pydantic = Rule.from_orm(rule)
        data_value = getattr(packet, rule_pydantic.data_field, None) if rule_pydantic.data_field else packet.model_dump_json()
        if check_rule_match(rule_pydantic, data_value):
            db_alert = AlertDB(
                timestamp=packet.timestamp,
                severity=rule_pydantic.severity,
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                description=f"Network traffic matched rule: {rule_pydantic.name} (Pattern: '{rule_pydantic.pattern}' in field '{rule_pydantic.data_field if rule_pydantic.data_field else 'all fields'}', Match Type: {rule_pydantic.match_type})"
            )
            db.add(db_alert)
            db.commit()
            db.refresh(db_alert)
            alert = Alert.from_orm(db_alert)
            print(f"Alert generated from network: {alert}")
            return

def process_system_log(log: SystemLogData, db: Session = Depends(get_db)):
    print(f"Processing system log: {log}")
    for rule in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["logs", "both"])).all():
        rule_pydantic = Rule.from_orm(rule)
        data_value = getattr(log, rule_pydantic.data_field, None) if rule_pydantic.data_field else log.model_dump_json()
        if check_rule_match(rule_pydantic, data_value):
            db_alert = AlertDB(
                timestamp=log.timestamp,
                severity=rule_pydantic.severity,
                source_ip=None,
                destination_ip=None,
                description=f"System log matched rule: {rule_pydantic.name} (Pattern: '{rule_pydantic.pattern}' in field '{rule_pydantic.data_field if rule_pydantic.data_field else 'all fields'}', Match Type: {rule_pydantic.match_type}) - Log: {log.message}"
            )
            db.add(db_alert)
            db.commit()
            db.refresh(db_alert)
            alert = Alert.from_orm(db_alert)
            print(f"Alert generated from log: {alert}")
            return

@app.post("/network_data")
async def receive_network_data(packet_data: NetworkPacketData, db: Session = Depends(get_db)):
    print(f"Received network data: {packet_data}")
    process_network_data(packet_data, db)
    return {"message": "Network data received and processed"}

@app.post("/system_log")
async def receive_system_log(log_data: SystemLogData, db: Session = Depends(get_db)):
    print(f"Received system log: {log_data}")
    process_system_log(log_data, db)
    return {"message": "System log received successfully"}

@app.get("/alerts", response_model=List[Alert])
async def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(AlertDB).all()
    return [Alert.from_orm(alert) for alert in alerts]

@app.get("/rules", response_model=List[Rule])
async def get_rules(db: Session = Depends(get_db)):
    rules = db.query(RuleDB).all()
    return [Rule.from_orm(rule) for rule in rules]

@app.post("/rules", response_model=Rule, status_code=201)
async def create_rule(rule: Rule, db: Session = Depends(get_db)):
    db_rule = RuleDB(**rule.model_dump())
    db.add(db_rule)
    try:
        db.commit()
        db.refresh(db_rule)
        return Rule.from_orm(db_rule)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {e}")

@app.get("/rules/{rule_id}", response_model=Rule)
async def get_rule(rule_id: int, db: Session = Depends(get_db)):
    db_rule = db.query(RuleDB).filter(RuleDB.id == rule_id).first()
    if db_rule is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    return Rule.from_orm(db_rule)

@app.put("/rules/{rule_id}", response_model=Rule)
async def update_rule(rule_id: int, updated_rule: Rule, db: Session = Depends(get_db)):
    db_rule = db.query(RuleDB).filter(RuleDB.id == rule_id).first()
    if db_rule is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    update_data = updated_rule.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_rule, key, value)
    try:
        db.commit()
        db.refresh(db_rule)
        return Rule.from_orm(db_rule)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {e}")

@app.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    db_rule = db.query(RuleDB).filter(RuleDB.id == rule_id).first()
    if db_rule is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    db.delete(db_rule)
    db.commit()
    return

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