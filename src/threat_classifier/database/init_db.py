import logging
from sqlalchemy import create_engine
from .models import Base
from .connection import db
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

def init_database():
    """Initialize the database by creating all tables"""
    try:
        # Use the existing database connection instance
        # This will automatically handle PostgreSQL/SQLite fallback
        logger.info("Initializing database tables...")
        
        # Create all tables using the configured engine
        Base.metadata.create_all(db.engine)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    init_database()