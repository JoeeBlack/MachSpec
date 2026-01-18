from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Service(Base):
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True, nullable=False) # Mach service name
    binary_path = Column(String, nullable=True)
    bundle_id = Column(String, index=True, nullable=True)
    plist_path = Column(String, nullable=True)
    
    # Metadata
    is_root = Column(Boolean, default=False)
    entitlements = Column(JSON, nullable=True)
    codesign_requirements = Column(Text, nullable=True)
    
    # Discovery info
    discovery_source = Column(String, nullable=True) # e.g., "LaunchDaemon", "AppBundle"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Service(name='{self.name}', binary='{self.binary_path}')>"
