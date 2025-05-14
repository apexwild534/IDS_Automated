from fastapi import FastAPI, HTTPException, Depends
from typing import List, Dict
from datetime import datetime, timedelta
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData, Condition, SequenceCondition
import re
from database import engine, Base, SessionLocal, AlertDB, RuleDB
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import column

Base.metadata.create_all(bind=engine)

app = FastAPI()

rule_event_timestamps: Dict[int, List[datetime]] = {}
# Dictionary to track ongoing event sequences: {(rule_id, source_identifier): (next_expected_index, start_time)}
active_sequences: Dict[tuple[int, str], tuple[int, datetime]] = {}

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
        sequence_data = rule_db.sequence if rule_db.sequence is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data],
            threshold_count=rule_db.threshold_count,
            threshold_window=rule_db.threshold_window,
            sequence=[SequenceCondition(**s) for s in sequence_data],
            sequence_window=rule_db.sequence_window
        )

        source_identifier = packet.source_ip

        if rule.sequence and rule.sequence_window:
            rule_id = rule.id
            sequence_key = (rule_id, source_identifier)

            if sequence_key in active_sequences:
                next_index, start_time = active_sequences[sequence_key]
                if next_index < len(rule.sequence):
                    expected_sequence_item = rule.sequence[next_index]
                    if expected_sequence_item.data_source == "network" and evaluate_condition(packet, expected_sequence_item.condition):
                        if next_index == len(rule.sequence) - 1:
                            # Sequence complete!
                            alert = AlertDB(
                                timestamp=datetime.utcnow(),
                                severity=rule.severity,
                                source_ip=packet.source_ip,
                                destination_ip=packet.destination_ip,
                                description=f"Sequential rule '{rule.name}' triggered (Sequence: {[s.model_dump() for s in rule.sequence]})"
                            )
                            db.add(alert)
                            db.commit()
                            db.refresh(alert)
                            print(f"Sequential alert generated from network: {Alert.from_orm(alert)}")
                            del active_sequences[sequence_key]
                            return
                        else:
                            # Move to the next step in the sequence
                            active_sequences[sequence_key] = (next_index + 1, start_time)
                            print(f"Network sequence for rule {rule_id}, source {source_identifier} advanced to step {next_index + 1}")
            elif len(rule.sequence) > 0:
                # Start of a new sequence
                first_sequence_item = rule.sequence[0]
                if first_sequence_item.data_source == "network" and evaluate_condition(packet, first_sequence_item.condition):
                    active_sequences[sequence_key] = (1, datetime.utcnow())
                    print(f"Network sequence for rule {rule_id}, source {source_identifier} started")

        elif rule.conditions: # Existing single-event rule logic
            all_conditions_met = True
            for condition in rule.conditions:
                if not evaluate_condition(packet, condition):
                    all_conditions_met = False
                    break
            if all_conditions_met:
                # ... (rest of the single-event alert logic - thresholding is already handled here)
                if rule.threshold_count is not None and rule.threshold_window is not None:
                    rule_id = rule.id
                    now = datetime.utcnow()
                    if rule_id not in rule_event_timestamps:
                        rule_event_timestamps[rule_id] = []
                    rule_event_timestamps[rule_id].append(now)
                    window_start = now - timedelta(seconds=rule.threshold_window)
                    rule_event_timestamps[rule_id] = [ts for ts in rule_event_timestamps[rule_id] if ts >= window_start]
                    if len(rule_event_timestamps[rule_id]) >= rule.threshold_count:
                        alert = AlertDB(
                            timestamp=now,
                            severity=rule.severity,
                            source_ip=packet.source_ip,
                            destination_ip=packet.destination_ip,
                            description=f"Threshold exceeded for rule '{rule.name}'. Triggered {len(rule_event_timestamps[rule_id])} times within {rule.threshold_window} seconds (Conditions: {[c.model_dump() for c in rule.conditions]})"
                        )
                        db.add(alert)
                        db.commit()
                        db.refresh(alert)
                        print(f"Threshold alert generated from network: {Alert.from_orm(alert)}")
                        return
                else:
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
        elif not rule.conditions and not rule.sequence:
            print(f"Encountered rule '{rule.name}' with no conditions or sequence. No alert triggered.")

def process_system_log(log: SystemLogData, db: Session = Depends(get_db)):
    print(f"Processing system log: {log}")
    for rule_db in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["logs", "both"])).all():
        conditions_data = rule_db.conditions if rule_db.conditions is not None else []
        sequence_data = rule_db.sequence if rule_db.sequence is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data],
            threshold_count=rule_db.threshold_count,
            threshold_window=rule_db.threshold_window,
            sequence=[SequenceCondition(**s) for s in sequence_data],
            sequence_window=rule_db.sequence_window
        )

        source_identifier = log.hostname # Using hostname as identifier for logs

        if rule.sequence and rule.sequence_window:
            rule_id = rule.id
            sequence_key = (rule_id, source_identifier)

            if sequence_key in active_sequences:
                next_index, start_time = active_sequences[sequence_key]
                if next_index < len(rule.sequence):
                    expected_sequence_item = rule.sequence[next_index]
                    if expected_sequence_item.data_source == "logs" and evaluate_condition(log, expected_sequence_item.condition):
                        if next_index == len(rule.sequence) - 1:
                            # Sequence complete!
                            alert = AlertDB(
                                timestamp=datetime.utcnow(),
                                severity=rule.severity,
                                source_ip=None,
                                destination_ip=None,
                                description=f"Sequential rule '{rule.name}' triggered (Sequence: {[s.model_dump() for s in rule.sequence]}) - Log Host: {log.hostname}"
                            )
                            db.add(alert)
                            db.commit()
                            db.refresh(alert)
                            print(f"Sequential alert generated from log: {Alert.from_orm(alert)}")
                            del active_sequences[sequence_key]
                            return
                        else:
                            # Move to the next step in the sequence
                            active_sequences[sequence_key] = (next_index + 1, start_time)
                            print(f"Log sequence for rule {rule_id}, host {source_identifier} advanced to step {next_index + 1}")
            elif len(rule.sequence) > 0:
                # Start of a new sequence
                first_sequence_item = rule.sequence[0]
                if first_sequence_item.data_source == "logs" and evaluate_condition(log, first_sequence_item.condition):
                    active_sequences[sequence_key] = (1, datetime.utcnow())
                    print(f"Log sequence for rule {rule_id}, host {source_identifier} started")

        elif rule.conditions: # Existing single-event rule logic for logs
            all_conditions_met = True
            for condition in rule.conditions:
                if not evaluate_condition(log, condition):
                    all_conditions_met = False
                    break
            if all_conditions_met:
                # ... (rest of the single-event log alert logic - thresholding is already handled)
                if rule.threshold_count is not None and rule.threshold_window is not None:
                    rule_id = rule.id
                    now = datetime.utcnow()
                    if rule_id not in rule_event_timestamps:
                        rule_event_timestamps[rule_id] = []
                    rule_event_timestamps[rule_id].append(now)
                    window_start = now - timedelta(seconds=rule.threshold_window)
                    rule_event_timestamps[rule_id] = [ts for ts in rule_event_timestamps[rule_id] if ts >= window_start]
                    if len(rule_event_timestamps[rule_id]) >= rule.threshold_count:
                        alert = AlertDB(
                            timestamp=now,
                            severity=rule.severity,
                            source_ip=None,
                            destination_ip=None,
                            description=f"Threshold exceeded for rule '{rule.name}'. Triggered {len(rule_event_timestamps[rule_id])} times within {rule.threshold_window} seconds (Conditions: {[c.model_dump() for c in rule.conditions]}) - Log: {log.message}"
                        )
                        db.add(alert)
                        db.commit()
                        db.refresh(alert)
                        print(f"Threshold alert generated from log: {Alert.from_orm(alert)}")
                        return
                else:
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
        elif not rule.conditions and not rule.sequence:
            print(f"Encountered rule '{rule.name}' with no conditions or sequence. No alert triggered.")

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
        sequence_data = rule_db.sequence if rule_db.sequence is not None else []
        rule = Rule(
            id=rule_db.id,
            name=rule_db.name,
            description=rule_db.description,
            severity=rule_db.severity,
            is_active=rule_db.is_active,
            data_source=rule_db.data_source,
            conditions=[Condition(**c) for c in conditions_data],
            threshold_count=rule_db.threshold_count,
            threshold_window=rule_db.threshold_window,
            sequence=[SequenceCondition(**s) for s in sequence_data],
            sequence_window=rule_db.sequence_window
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

@app.get("/rules/{rule_id}", response_model=Rule)
async def get_rule(rule_id: int, db: Session = Depends(get_db)):
    db_rule = db.query(RuleDB).filter(RuleDB.id == rule_id).first()
    if db_rule is None:
        raise HTTPException(status_code=404, detail=f"Rule with ID {rule_id} not found")
    conditions_data = db_rule.conditions if db_rule.conditions is not None else []
    sequence_data = db_rule.sequence if db_rule.sequence is not None else []
    return Rule(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        severity=db_rule.severity,
        is_active=db_rule.is_active,
        data_source=db_rule.data_source,
        conditions=[Condition(**c) for c in conditions_data],
        threshold_count=db_rule.threshold_count,
        threshold_window=db_rule.threshold_window,
        sequence=[SequenceCondition(**s) for s in sequence_data],
        sequence_window=db_rule.sequence_window
    )

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