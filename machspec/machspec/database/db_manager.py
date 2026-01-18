from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base
import os

class DBManager:
    def __init__(self, db_path="machspec.db"):
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}")
        self.Session = sessionmaker(bind=self.engine)
        
    def init_db(self):
        """Initialize the database schema."""
        Base.metadata.create_all(self.engine)
        
    def get_session(self):
        """Get a new session."""
        return self.Session()
