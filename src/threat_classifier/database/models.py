from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class AnalysisSession(Base):
    __tablename__ = 'analysis_sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), unique=True, nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    total_records = Column(Integer)
    threat_distribution = Column(JSON)  # Store as JSON: {"Low": count, "Medium": count, "High": count}
    report_path = Column(String(255))
    analysis_type = Column(String(50))  # 'file_upload' or 'text_input'
    
    # Relationships
    log_entries = relationship("LogEntry", back_populates="session")
    threat_events = relationship("ThreatEvent", back_populates="session")

class LogEntry(Base):
    __tablename__ = 'log_entries'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey('analysis_sessions.session_id'))
    log_text = Column(String(1000))
    threat_level = Column(String(20))  # 'Low', 'Medium', 'High'
    confidence = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("AnalysisSession", back_populates="log_entries")

class ThreatEvent(Base):
    __tablename__ = 'threat_events'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey('analysis_sessions.session_id'))
    event_type = Column(String(50))  # 'file_upload', 'analysis_start', 'analysis_complete', etc.
    event_details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("AnalysisSession", back_populates="threat_events") 