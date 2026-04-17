"""
Database models and connection management using SQLAlchemy ORM.
"""
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash
import config

Base = declarative_base()


class RawLog(Base):
    """Raw CloudTrail event logs."""
    __tablename__ = 'raw_logs'
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(100), unique=True, nullable=False, index=True)
    user = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45))
    action = Column(String(255), nullable=False)
    resource = Column(String(500))
    region = Column(String(50))
    outcome = Column(String(50))
    raw_data = Column(Text)
    
    # Relationships
    features = relationship('Feature', back_populates='log', uselist=False)
    alerts = relationship('Alert', back_populates='log')
    
    def __repr__(self):
        return f"<RawLog(event_id='{self.event_id}', user='{self.user}', action='{self.action}')>"


class Feature(Base):
    """Engineered features for ML model."""
    __tablename__ = 'features'
    
    id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey('raw_logs.id'), nullable=False, unique=True)
    login_frequency = Column(Float)
    api_call_count = Column(Integer)
    time_of_access = Column(Integer)
    geo_deviation = Column(Integer)
    privilege_weight = Column(Float)
    failed_login_count = Column(Integer)
    resource_sensitivity = Column(Float)
    
    # Relationships
    log = relationship('RawLog', back_populates='features')
    
    def __repr__(self):
        return f"<Feature(log_id={self.log_id}, privilege_weight={self.privilege_weight})>"


class Alert(Base):
    """Security alerts generated from anomaly detection."""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey('raw_logs.id'), nullable=False)
    threat_type = Column(String(100), nullable=False)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default='open', index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    closed_at = Column(DateTime)
    closed_by = Column(Integer, ForeignKey('users.id'))
    
    # Relationships
    log = relationship('RawLog', back_populates='alerts')
    closer = relationship('User', foreign_keys=[closed_by])
    
    def __repr__(self):
        return f"<Alert(id={self.id}, severity='{self.severity}', status='{self.status}')>"


class User(Base):
    """Dashboard users with RBAC."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default='analyst')
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def set_password(self, password: str):
        """Hash and set password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Verify password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f"<User(username='{self.username}', role='{self.role}')>"


# Database engine and session
engine = create_engine(config.DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(engine)
    print("Database initialized successfully!")
    
    # Create default admin user if not exists
    session = SessionLocal()
    try:
        admin = session.query(User).filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            session.add(admin)
            session.commit()
            print("Default admin user created (username: admin, password: admin123)")
    finally:
        session.close()


def get_session():
    """Get database session."""
    return SessionLocal()
