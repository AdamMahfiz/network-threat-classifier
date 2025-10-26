#!/usr/bin/env python3
"""
Database migration script to add missing user_id column to analysis_sessions table
"""

import os
import sys
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def migrate_database():
    """Add missing user_id column to analysis_sessions table"""
    print("Starting database migration...")
    
    try:
        # Get database URL
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise ValueError("DATABASE_URL environment variable is not set")
        
        # Create engine
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            # Check if user_id column exists
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'analysis_sessions' 
                AND column_name = 'user_id'
            """))
            
            if result.fetchone() is None:
                print("Adding user_id column to analysis_sessions table...")
                conn.execute(text("""
                    ALTER TABLE analysis_sessions 
                    ADD COLUMN user_id INTEGER REFERENCES users(id)
                """))
                conn.commit()
                print("✓ user_id column added successfully")
            else:
                print("✓ user_id column already exists")
        
        print("✓ Database migration completed successfully")
        
    except Exception as e:
        print(f"✗ Error during migration: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    migrate_database()