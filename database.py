from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./sentinelai.db"  # SQLite database file

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    description = Column(String)

class RuleDB(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=True)
    severity = Column(String)
    is_active = Column(Boolean, default=True)
    data_source = Column(String, default="both")
    conditions = Column(JSON) # Store conditions as a JSON structure
    threshold_count = Column(Integer, nullable=True)
    threshold_window = Column(Integer, nullable=True)
    sequence = Column(JSON, nullable=True) # Store sequence as JSON
    sequence_window = Column(Integer, nullable=True)
    coincidence_conditions = Column(JSON, nullable=True) # For coincidence rules
    coincidence_window = Column(Integer, nullable=True) # Window for coincidence
    aggregation_field = Column(String, nullable=True) # Field to aggregate on
    aggregation_value = Column(String, nullable=True) # Expected value after aggregation
    aggregation_count = Column(Integer, nullable=True) # Expected count after aggregation
    aggregation_window = Column(Integer, nullable=True) # Window for aggregation
    anomaly_field = Column(String, nullable=True) # Field to check for anomaly
    anomaly_threshold_multiplier = Column(Float, nullable=True) # Multiplier for std dev
    anomaly_window = Column(Integer, nullable=True) # Window to calculate baseline
    anomaly_baseline_count = Column(Integer, nullable=True) # Min events for baseline