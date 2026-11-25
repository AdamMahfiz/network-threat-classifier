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
        """Initialise the engine from DATABASE_URL, falling back to a SQLite file.

        DATABASE_URL (e.g. postgresql+psycopg2://user:pass@host/db) takes precedence.
        Without it, SQLITE_DATABASE_PATH (default data/threat_classifier.db) is used.
        """
        try:
            database_url = os.getenv('DATABASE_URL', '').strip()
            if database_url:
                self._create_engine_from_url(database_url)
                logger.info("Database connection initialised from DATABASE_URL")
            else:
                sqlite_path = os.getenv('SQLITE_DATABASE_PATH', 'data/threat_classifier.db')
                self._create_sqlite_engine(sqlite_path)
                logger.info("SQLite database connection initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialise database connection: {str(e)}")
            raise

    def _create_engine_from_url(self, database_url):
        """Create an engine for a server database (PostgreSQL, MySQL, ...)."""
        self.engine = create_engine(
            database_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=int(os.getenv('DB_POOL_SIZE', '5')),
            max_overflow=int(os.getenv('DB_MAX_OVERFLOW', '10')),
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        with self.engine.connect() as conn:
            conn.execute(text('SELECT 1'))

    def _create_sqlite_engine(self, sqlite_path):
        """Create SQLite engine with appropriate configuration"""
        # Ensure the directory exists
        os.makedirs(os.path.dirname(sqlite_path) or '.', exist_ok=True)
        
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
        """Get database connection information (works for SQLite and server databases)"""
        if not self.engine:
            return {"status": "disconnected", "type": "unknown"}

        dialect = self.engine.dialect.name
        try:
            with self.engine.connect() as conn:
                if dialect == 'sqlite':
                    row = conn.execute(text("PRAGMA database_list")).fetchone()
                    database = row[2] if row else "unknown"
                else:
                    database = conn.execute(text("SELECT current_database()")).scalar()

                return {
                    "status": "connected",
                    "type": dialect,
                    "database": database,
                    "url": self.engine.url.render_as_string(hide_password=True),
                }
        except Exception as e:
            return {
                "status": "error",
                "type": dialect,
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