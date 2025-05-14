from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./sentinelai.db"  # SQLite database file

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
# Base.metadata.drop_all(bind=engine) # Remove this after initial schema update
# Base.metadata.create_all(bind=engine) # Remove this after initial schema update

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