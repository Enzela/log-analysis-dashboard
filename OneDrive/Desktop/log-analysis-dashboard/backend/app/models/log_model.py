from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class LogFile(Base):
    __tablename__ = "log_files"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    file_name = Column(String(255))
    uploaded_at = Column(DateTime, default=func.now())

class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True, index=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id"))
    timestamp = Column(DateTime)
    source_ip = Column(String(50))
    event_type = Column(String(100))
    raw_log = Column(Text)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    log_entry_id = Column(Integer, ForeignKey("log_entries.id"))
    threat_type = Column(String(100))
    severity = Column(String(20))
    confidence_score = Column(Float)
    status = Column(String(50))