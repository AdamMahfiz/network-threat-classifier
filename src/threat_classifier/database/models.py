from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, JSON, ForeignKey, Boolean, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

Base = declarative_base()

# User-Role association table for many-to-many relationship
user_roles = Table('user_roles', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)

class User(UserMixin, Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    first_name = Column(String(64))
    last_name = Column(String(64))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    totp_secret = Column(String(32))  # For 2FA
    
    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    analysis_sessions = relationship('AnalysisSession', back_populates='user')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_totp_secret(self):
        # Generate a random secret for TOTP-based 2FA
        import pyotp
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    # Flask-Login required methods
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def has_role(self, role_name):
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
    
    @property
    def two_factor_enabled(self):
        """Check if 2FA is enabled for this user"""
        return self.totp_secret is not None

class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(256))
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')

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
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Relationships
    log_entries = relationship("LogEntry", back_populates="session")
    threat_events = relationship("ThreatEvent", back_populates="session")
    user = relationship("User", back_populates="analysis_sessions")

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