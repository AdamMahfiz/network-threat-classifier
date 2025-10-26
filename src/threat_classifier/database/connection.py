import os
import time
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class DatabaseConnection:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize database connection using SQLite exclusively"""
        # Use SQLite as the primary and only database
        try:
            sqlite_path = os.getenv('SQLITE_DATABASE_PATH', 'data/threat_classifier.db')
            self._create_sqlite_engine(sqlite_path)
            logger.info("SQLite database connection initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SQLite database connection: {str(e)}")
            raise
    
    def _create_sqlite_engine(self, sqlite_path):
        """Create SQLite engine with appropriate configuration"""
        # Ensure the directory exists
        os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
        
        sqlite_url = f"sqlite:///{sqlite_path}"
        self.engine = create_engine(
            sqlite_url,
            echo=False,
            connect_args={
                "check_same_thread": False,  # Allow SQLite to be used across threads
                "timeout": 20  # 20 second timeout for database locks
            }
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        # Test the connection
        with self.engine.connect() as conn:
            conn.execute(text('SELECT 1'))
    
    def get_session(self):
        """Get a new database session with retry logic"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
             session = None
             try:
                 session = self.SessionLocal()
                 # Test the connection
                 session.execute(text('SELECT 1'))
                 return session
             except Exception as e:
                 retry_count += 1
                 logger.warning(f"Database session creation attempt {retry_count} failed: {str(e)}")
                 
                 # Close the failed session if it was created
                 if session:
                     try:
                         session.close()
                     except:
                         pass
                 
                 if retry_count >= max_retries:
                     logger.error(f"Failed to create database session after {max_retries} attempts: {str(e)}")
                     raise
                 
                 # If it's an SSL connection error, try to recreate the engine
                 if "SSL connection has been closed" in str(e) or "connection" in str(e).lower():
                     logger.info("Attempting to recreate database engine due to connection issue")
                     try:
                         self._initialize()
                     except Exception as init_error:
                         logger.error(f"Failed to reinitialize database connection: {str(init_error)}")
                 
                 # Wait a bit before retrying
                 time.sleep(1)
    
    def get_database_info(self):
        """Get database connection information"""
        if not self.engine:
            return {"status": "disconnected", "type": "unknown"}
        
        try:
            with self.engine.connect() as conn:
                # For SQLite, get database file info
                result = conn.execute(text("PRAGMA database_list"))
                db_info = result.fetchone()
                
                return {
                    "status": "connected",
                    "type": "sqlite",
                    "database": db_info[2] if db_info else "unknown",
                    "url": str(self.engine.url).replace(str(self.engine.url.password), '***') if self.engine.url.password else str(self.engine.url)
                }
        except Exception as e:
            return {
                "status": "error",
                "type": "sqlite",
                "error": str(e)
            }
    
    def close(self):
        """Close the database connection"""
        try:
            if hasattr(self, 'engine'):
                self.engine.dispose()
                logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {str(e)}")
            raise

# Create a global database connection instance
db = DatabaseConnection()