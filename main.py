from fastapi import FastAPI, HTTPException, Depends
from typing import List
from datetime import datetime
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData, Condition
import re
from database import engine, Base, SessionLocal, AlertDB, RuleDB
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import column

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def evaluate_condition(data_item, condition: Condition) -> bool:
    field_value = getattr(data_item, condition.field, None)
    if field_value is None:
        return False

    value_to_compare = str(field_value)
    condition_value = condition.value

    if condition.operator == "equals":
        return value_to_compare == condition_value
    elif condition.operator == "not_equals":
        return value_to_compare != condition_value
    elif condition.operator == "contains":
        return condition_value in value_to_compare
    elif condition.operator == "not_contains":
        return condition_value not in value_to_compare
    elif condition.operator == "regex":
        return re.search(condition_value, value_to_compare, re.IGNORECASE) is not None
    elif condition.operator == "greater_than":
        try:
            return float(value_to_compare) > float(condition_value)
        except ValueError:
            return False
    elif condition.operator == "less_than":
        try:
            return float(value_to_compare) < float(condition_value)
        except ValueError:
            return False
    return False

def process_network_data(packet: NetworkPacketData, db: Session = Depends(get_db)):
    print(f"Processing network data: {packet}")
    for rule_db in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["network", "both"])).all():
        conditions_data = rule_db.conditions if rule_db.conditions is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data]
        )
        if rule.conditions:  # Check if there are any conditions
            all_conditions_met = True
            for condition in rule.conditions:
                if not evaluate_condition(packet, condition):
                    all_conditions_met = False
                    break
            if all_conditions_met:
                alert = AlertDB(
                    timestamp=packet.timestamp,
                    severity=rule.severity,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    description=f"Network traffic matched rule: {rule.name} (Conditions: {[c.model_dump() for c in rule.conditions]})"
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)
                print(f"Alert generated from network: {Alert.from_orm(alert)}")
                return
        elif not rule.conditions: # Handle rules with no conditions (e.g., the old "Test Rule") - maybe trigger on any matching data source?
            # You might want to define specific behavior for rules with no conditions.
            # For now, let's just log that we encountered one.
            print(f"Encountered rule '{rule.name}' with no conditions. No alert triggered.")

def process_system_log(log: SystemLogData, db: Session = Depends(get_db)):
    print(f"Processing system log: {log}")
    for rule_db in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["logs", "both"])).all():
        conditions_data = rule_db.conditions if rule_db.conditions is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data]
        )
        if rule.conditions:
            all_conditions_met = True
            for condition in rule.conditions:
                if not evaluate_condition(log, condition):
                    all_conditions_met = False
                    break
            if all_conditions_met:
                alert = AlertDB(
                    timestamp=log.timestamp,
                    severity=rule.severity,
                    source_ip=None,
                    destination_ip=None,
                    description=f"System log matched rule: {rule.name} (Conditions: {[c.model_dump() for c in rule.conditions]}) - Log: {log.message}"
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)
                print(f"Alert generated from log: {Alert.from_orm(alert)}")
                return
        elif not rule.conditions:
            print(f"Encountered rule '{rule.name}' with no conditions. No alert triggered.")

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
    rules_db = db.query(RuleDB).all()
    rules = []
    for rule_db in rules_db:
        conditions_data = rule_db.conditions if rule_db.conditions is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data]
        )
        rules.append(rule)
    return rules
@app.post("/rules", response_model=Rule, status_code=201)
async def create_rule(rule: Rule, db: Session = Depends(get_db)):
    db_rule = RuleDB(**rule.model_dump(exclude={"id"}))
    db.add(db_rule)
    try:
        db.commit()
        db.refresh(db_rule)
        return Rule.from_orm(db_rule)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Database error: {e}")

@app.put("/rules/{rule_id}", response_model=Rule)
async def update_rule(rule_id: int, updated_rule: Rule, db: Session = Depends(get_db)):
    db_rule = db.query(RuleDB).filter(RuleDB.id == rule_id).first()
    if db_rule is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    update_data = updated_rule.model_dump(exclude_unset=True, exclude={"id"})
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