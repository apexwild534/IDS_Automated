from fastapi import FastAPI, HTTPException, Depends
from typing import List, Dict
from datetime import datetime, timedelta
from models import Alert, Rule, SystemStatus, NetworkPacketData, SystemLogData, Condition, SequenceCondition, CoincidenceCondition
import re
from database import engine, Base, SessionLocal, AlertDB, RuleDB
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import column
from sqlalchemy import func
from collections import defaultdict
import numpy as np

Base.metadata.create_all(bind=engine)

app = FastAPI()

rule_event_timestamps: Dict[int, List[datetime]] = defaultdict(list)
active_sequences: Dict[tuple[int, str], tuple[int, datetime]] = {}
coincidence_event_buffers: Dict[int, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
anomaly_baselines: Dict[int, Dict[str, tuple[float, float, int]]] = defaultdict(lambda: defaultdict(lambda: (0.0, 0.0, 0))) # {rule_id: {field: (mean, std_dev, count)}}

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
        coincidence_data = rule_db.coincidence_conditions if rule_db.coincidence_conditions is not None else []
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
            sequence_window=rule_db.sequence_window,
            coincidence_conditions=[CoincidenceCondition(**cc) for cc in coincidence_data],
            coincidence_window=rule_db.coincidence_window,
            aggregation_field=rule_db.aggregation_field,
            aggregation_value=rule_db.aggregation_value,
            aggregation_count=rule_db.aggregation_count,
            aggregation_window=rule_db.aggregation_window,
            anomaly_field=rule_db.anomaly_field,
            anomaly_threshold_multiplier=rule_db.anomaly_threshold_multiplier,
            anomaly_window=rule_db.anomaly_window,
            anomaly_baseline_count=rule_db.anomaly_baseline_count
        )

        source_identifier = packet.source_ip

        if rule.anomaly_field and rule.anomaly_threshold_multiplier and rule.anomaly_window and rule.anomaly_baseline_count is not None:
            process_anomaly_detection(rule, packet, db)
            continue # Anomaly detection is handled separately

        if rule.aggregation_field and rule.aggregation_value and rule.aggregation_count and rule.aggregation_window:
            process_aggregation_rule(rule, packet, db)
            continue # Aggregation rule is handled separately

        if rule.coincidence_conditions and rule.coincidence_window:
            process_coincidence_rule(rule, packet, "network", db)
            continue

        if rule.sequence and rule.sequence_window:
            process_sequence_rule(rule, packet, "network", source_identifier, db)
            continue

        if rule.conditions: # Existing single-event rule logic
            process_single_event_rule(rule, packet, source_identifier, db)

def process_system_log(log: SystemLogData, db: Session = Depends(get_db)):
    print(f"Processing system log: {log}")
    for rule_db in db.query(RuleDB).filter(RuleDB.is_active == True, RuleDB.data_source.in_(["logs", "both"])).all():
        conditions_data = rule_db.conditions if rule_db.conditions is not None else []
        sequence_data = rule_db.sequence if rule_db.sequence is not None else []
        coincidence_data = rule_db.coincidence_conditions if rule_db.coincidence_conditions is not None else []
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
            sequence_window=rule_db.sequence_window,
            coincidence_conditions=[CoincidenceCondition(**cc) for cc in coincidence_data],
            coincidence_window=rule_db.coincidence_window,
            aggregation_field=rule_db.aggregation_field,
            aggregation_value=rule_db.aggregation_value,
            aggregation_count=rule_db.aggregation_count,
            aggregation_window=rule_db.aggregation_window,
            anomaly_field=rule_db.anomaly_field,
            anomaly_threshold_multiplier=rule_db.anomaly_threshold_multiplier,
            anomaly_window=rule_db.anomaly_window,
            anomaly_baseline_count=rule_db.anomaly_baseline_count
        )

        source_identifier = log.hostname # Using hostname as identifier for logs

        if rule.anomaly_field and rule.anomaly_threshold_multiplier and rule.anomaly_window and rule.anomaly_baseline_count is not None:
            process_anomaly_detection(rule, log, db)
            continue # Anomaly detection is handled separately

        if rule.aggregation_field and rule.aggregation_value and rule.aggregation_count and rule.aggregation_window:
            process_aggregation_rule(rule, log, db)
            continue # Aggregation rule is handled separately

        if rule.coincidence_conditions and rule.coincidence_window:
            process_coincidence_rule(rule, log, "logs", db)
            continue

        if rule.sequence and rule.sequence_window:
            process_sequence_rule(rule, log, "logs", source_identifier, db)
            continue

        if rule.conditions: # Existing single-event rule logic for logs
            process_single_event_rule(rule, log, source_identifier, db)

def process_single_event_rule(rule: Rule, data_item, source_identifier: str, db: Session):
    all_conditions_met = True
    for condition in rule.conditions:
        if not evaluate_condition(data_item, condition):
            all_conditions_met = False
            break
    if all_conditions_met:
        if rule.threshold_count is not None and rule.threshold_window is not None:
            now = datetime.utcnow()
            rule_event_timestamps[rule.id].append(now)
            window_start = now - timedelta(seconds=rule.threshold_window)
            rule_event_timestamps[rule.id] = [ts for ts in rule_event_timestamps[rule.id] if ts >= window_start]
            if len(rule_event_timestamps[rule.id]) >= rule.threshold_count:
                alert = AlertDB(
                    timestamp=now,
                    severity=rule.severity,
                    source_ip=getattr(data_item, 'source_ip', None),
                    destination_ip=getattr(data_item, 'destination_ip', None),
                    description=f"Threshold exceeded for rule '{rule.name}'. Triggered {len(rule_event_timestamps[rule.id])} times within {rule.threshold_window} seconds (Conditions: {[c.model_dump() for c in rule.conditions]}) - Source: {source_identifier}"
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)
                print(f"Threshold alert generated: {Alert.from_orm(alert)}")
                rule_event_timestamps[rule.id] = [] # Reset timestamps after alert
        else:
            alert = AlertDB(
                timestamp=getattr(data_item, 'timestamp', datetime.utcnow()),
                severity=rule.severity,
                source_ip=getattr(data_item, 'source_ip', None),
                destination_ip=getattr(data_item, 'destination_ip', None),
                description=f"{data_item.__class__.__name__} matched rule: {rule.name} (Conditions: {[c.model_dump() for c in rule.conditions]}) - Source: {source_identifier}"
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            print(f"Alert generated: {Alert.from_orm(alert)}")

def process_sequence_rule(rule: Rule, data_item, data_source: str, source_identifier: str, db: Session):
    rule_id = rule.id
    sequence_key = (rule_id, source_identifier)
    now = datetime.utcnow()

    if sequence_key in active_sequences:
        next_index, start_time = active_sequences[sequence_key]
        if now - start_time <= timedelta(seconds=rule.sequence_window):
            if next_index < len(rule.sequence):
                expected_sequence_item = rule.sequence[next_index]
                if expected_sequence_item.data_source == data_source and evaluate_condition(data_item, expected_sequence_item.condition):
                    if next_index == len(rule.sequence) - 1:
                        # Sequence complete!
                        alert = AlertDB(
                            timestamp=now,
                            severity=rule.severity,
                            source_ip=getattr(data_item, 'source_ip', None),
                            destination_ip=getattr(data_item, 'destination_ip', None),
                            description=f"Sequential rule '{rule.name}' triggered (Sequence: {[s.model_dump() for s in rule.sequence]}) - Source: {source_identifier}"
                        )
                        db.add(alert)
                        db.commit()
                        db.refresh(alert)
                        print(f"Sequential alert generated from {data_source}: {Alert.from_orm(alert)}")
                        del active_sequences[sequence_key]
                    else:
                        active_sequences[sequence_key] = (next_index + 1, start_time)
                        print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} advanced to step {next_index + 1}")
                elif next_index == 0: # Restart sequence if first condition fails
                    first_sequence_item = rule.sequence[0]
                    if first_sequence_item.data_source == data_source and evaluate_condition(data_item, first_sequence_item.condition):
                        active_sequences[sequence_key] = (1, now)
                        print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} restarted")
                    else:
                        del active_sequences[sequence_key] # Sequence broken
                        print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} broken")
            else:
                del active_sequences[sequence_key] # Sequence completed or window expired
                print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} ended")
        else:
            del active_sequences[sequence_key] # Sequence window expired
            print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} timed out")
    elif len(rule.sequence) > 0:
        # Start of a new sequence
        first_sequence_item = rule.sequence[0]
        if first_sequence_item.data_source == data_source and evaluate_condition(data_item, first_sequence_item.condition):
            active_sequences[sequence_key] = (1, now)
            print(f"{data_source} sequence for rule {rule_id}, source {source_identifier} started")

def process_coincidence_rule(rule: Rule, data_item, data_source: str, db: Session):
    rule_id = rule.id
    source_identifier = getattr(data_item, 'source_ip', getattr(data_item, 'hostname', 'unknown'))
    now = datetime.utcnow()

    if rule_id not in coincidence_event_buffers:
        coincidence_event_buffers[rule_id] = defaultdict(list)

    for condition_group in rule.coincidence_conditions:
        if condition_group.data_source == data_source:
            group_key = tuple(sorted([c.field for c in condition_group.conditions])) # Unique key for the group
            if all(evaluate_condition(data_item, cond) for cond in condition_group.conditions):
                coincidence_event_buffers[rule_id][source_identifier].append((now, group_key))
                # Clean up old events
                window_start = now - timedelta(seconds=rule.coincidence_window)
                coincidence_event_buffers[rule_id][source_identifier] = [(ts, key) for ts, key in coincidence_event_buffers[rule_id][source_identifier] if ts >= window_start]

                # Check if all coincidence conditions have occurred within the window
                occurred_groups = set(key for _, key in coincidence_event_buffers[rule_id][source_identifier])
                required_groups = set(tuple(sorted([c.field for c in cg.conditions])) for cg in rule.coincidence_conditions if cg.data_source == data_source)

                if occurred_groups == required_groups and len(occurred_groups) == len(rule.coincidence_conditions):
                    alert = AlertDB(
                        timestamp=now,
                        severity=rule.severity,
                        source_ip=getattr(data_item, 'source_ip', None),
                        destination_ip=getattr(data_item, 'destination_ip', None),
                        description=f"Coincidence rule '{rule.name}' triggered. All conditions met within {rule.coincidence_window} seconds. Source: {source_identifier}"
                    )
                    db.add(alert)
                    db.commit()
                    db.refresh(alert)
                    print(f"Coincidence alert generated from {data_source}: {Alert.from_orm(alert)}")
                    coincidence_event_buffers[rule_id][source_identifier] = [] # Reset buffer

def process_aggregation_rule(rule: Rule, data_item, db: Session):
    timestamp = getattr(data_item, 'timestamp', datetime.utcnow())
    field_value = getattr(data_item, rule.aggregation_field, None)
    if field_value is None:
        return

    aggregation_key = (rule.id, rule.aggregation_field, field_value)
    if aggregation_key not in rule_event_timestamps:
        rule_event_timestamps[aggregation_key] = []
    rule_event_timestamps[aggregation_key].append(timestamp)

    window_start = timestamp - timedelta(seconds=rule.aggregation_window)
    rule_event_timestamps[aggregation_key] = [ts for ts in rule_event_timestamps[aggregation_key] if ts >= window_start]

    if len(rule_event_timestamps[aggregation_key]) >= rule.aggregation_count:
        alert = AlertDB(
            timestamp=timestamp,
            severity=rule.severity,
            source_ip=getattr(data_item, 'source_ip', None),
            destination_ip=getattr(data_item, 'destination_ip', None),
            description=f"Aggregation rule '{rule.name}' triggered. {rule.aggregation_field}='{field_value}' occurred {len(rule_event_timestamps[aggregation_key])} times within {rule.aggregation_window} seconds, expected {rule.aggregation_count}."
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        print(f"Aggregation alert generated: {Alert.from_orm(alert)}")
        del rule_event_timestamps[aggregation_key] # Reset counter

def process_anomaly_detection(rule: Rule, data_item, db: Session):
    timestamp = getattr(data_item, 'timestamp', datetime.utcnow())
    value = getattr(data_item, rule.anomaly_field, None)
    if value is None:
        return

    try:
        numeric_value = float(value)
    except ValueError:
        print(f"Warning: Cannot perform anomaly detection on non-numeric value '{value}' for field '{rule.anomaly_field}'.")
        return

    rule_id = rule.id
    field_name = rule.anomaly_field

    if rule_id not in anomaly_baselines or field_name not in anomaly_baselines[rule_id] or anomaly_baselines[rule_id][field_name][2] < rule.anomaly_baseline_count:
        # Collect baseline data
        baseline_key = (rule_id, field_name)
        if baseline_key not in rule_event_timestamps:
            rule_event_timestamps[baseline_key] = []
        rule_event_timestamps[baseline_key].append(numeric_value)
        window_start = timestamp - timedelta(seconds=rule.anomaly_window)
        rule_event_timestamps[baseline_key] = [v for i, v in enumerate(rule_event_timestamps[baseline_key]) if i >= len(rule_event_timestamps[baseline_key]) - sum(1 for ts in [getattr(data_item, 'timestamp', datetime.utcnow()) for _ in rule_event_timestamps[baseline_key]] if ts >= window_start)]

        if len(rule_event_timestamps[baseline_key]) >= rule.anomaly_baseline_count:
            mean = np.mean(rule_event_timestamps[baseline_key])
            std_dev = np.std(rule_event_timestamps[baseline_key])
            anomaly_baselines[rule_id][field_name] = (mean, std_dev, len(rule_event_timestamps[baseline_key]))
            print(f"Established anomaly baseline for rule {rule_id}, field {field_name}: mean={mean:.2f}, std_dev={std_dev:.2f}, count={len(rule_event_timestamps[baseline_key])}")
        return

    mean, std_dev, count = anomaly_baselines[rule_id][field_name]
    threshold = mean + rule.anomaly_threshold_multiplier * std_dev

    if numeric_value > threshold:
        alert = AlertDB(
            timestamp=timestamp,
            severity=rule.severity,
            source_ip=getattr(data_item, 'source_ip', None),
            destination_ip=getattr(data_item, 'destination_ip', None),
            description=f"Anomaly detected for rule '{rule.name}'. {field_name}={numeric_value:.2f} exceeds threshold {threshold:.2f} (mean={mean:.2f}, std_dev={std_dev:.2f}) within baseline window."
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        print(f"Anomaly alert generated: {Alert.from_orm(alert)}")

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
        coincidence_data = rule_db.coincidence_conditions if rule_db.coincidence_conditions is not None else []
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
            sequence_window=rule_db.sequence_window,
            coincidence_conditions=[CoincidenceCondition(**cc) for cc in coincidence_data],
            coincidence_window=rule_db.coincidence_window,
            aggregation_field=rule_db.aggregation_field,
            aggregation_value=rule_db.aggregation_value,
            aggregation_count=rule_db.aggregation_count,
            aggregation_window=rule_db.aggregation_window,
            anomaly_field=rule_db.anomaly_field,
            anomaly_threshold_multiplier=rule_db.anomaly_threshold_multiplier,
            anomaly_window=rule_db.anomaly_window,
            anomaly_baseline_count=rule_db.anomaly_baseline_count
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
    coincidence_data = db_rule.coincidence_conditions if db_rule.coincidence_conditions is not None else []
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
        sequence_window=db_rule.sequence_window,
        coincidence_conditions=[CoincidenceCondition(**cc) for cc in coincidence_data],
        coincidence_window=db_rule.coincidence_window,
        aggregation_field=db_rule.aggregation_field,
        aggregation_value=db_rule.aggregation_value,
        aggregation_count=db_rule.aggregation_count,
        aggregation_window=db_rule.aggregation_window,
        anomaly_field=db_rule.anomaly_field,
        anomaly_threshold_multiplier=db_rule.anomaly_threshold_multiplier,
        anomaly_window=db_rule.anomaly_window,
        anomaly_baseline_count=db_rule.anomaly_baseline_count
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