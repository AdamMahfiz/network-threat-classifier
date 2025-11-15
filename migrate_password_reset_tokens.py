#!/usr/bin/env python3
"""
Migration script to fix password reset tokens foreign key constraint
This script adds CASCADE delete to the password_reset_tokens.user_id foreign key
"""

import sqlite3
import os
from pathlib import Path

def migrate_password_reset_tokens():
    """Migrate the password_reset_tokens table to add CASCADE delete"""
    
    # Database path
    db_path = Path("data/threat_classifier.db")
    
    if not db_path.exists():
        print(f"Database not found at {db_path}")
        return False
    
    try:
        # Connect to database
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        print("Starting password reset tokens migration...")
        
        # Check if password_reset_tokens table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='password_reset_tokens'
        """)
        
        if not cursor.fetchone():
            print("password_reset_tokens table does not exist. No migration needed.")
            conn.close()
            return True
        
        # Begin transaction
        cursor.execute("BEGIN TRANSACTION")
        
        # Step 1: Create new table with CASCADE delete
        cursor.execute("""
            CREATE TABLE password_reset_tokens_new (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(255) UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0
            )
        """)
        
        # Step 2: Copy data from old table to new table
        cursor.execute("""
            INSERT INTO password_reset_tokens_new 
            (id, user_id, token, created_at, expires_at, used)
            SELECT id, user_id, token, created_at, expires_at, used
            FROM password_reset_tokens
        """)
        
        # Step 3: Drop old table
        cursor.execute("DROP TABLE password_reset_tokens")
        
        # Step 4: Rename new table
        cursor.execute("ALTER TABLE password_reset_tokens_new RENAME TO password_reset_tokens")
        
        # Step 5: Create index on user_id for performance
        cursor.execute("""
            CREATE INDEX idx_password_reset_tokens_user_id 
            ON password_reset_tokens(user_id)
        """)
        
        # Step 6: Create index on token for performance
        cursor.execute("""
            CREATE UNIQUE INDEX idx_password_reset_tokens_token 
            ON password_reset_tokens(token)
        """)
        
        # Commit transaction
        cursor.execute("COMMIT")
        
        print("✓ Successfully migrated password_reset_tokens table with CASCADE delete")
        
        # Verify the migration
        cursor.execute("PRAGMA foreign_key_list(password_reset_tokens)")
        fk_info = cursor.fetchall()
        print(f"✓ Foreign key constraints: {len(fk_info)} found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Migration failed: {str(e)}")
        try:
            cursor.execute("ROLLBACK")
            conn.close()
        except:
            pass
        return False

if __name__ == "__main__":
    print("Password Reset Tokens Migration Script")
    print("=" * 50)
    
    success = migrate_password_reset_tokens()
    
    if success:
        print("\n✓ Migration completed successfully!")
        print("The password_reset_tokens table now has CASCADE delete configured.")
    else:
        print("\n✗ Migration failed!")
        print("Please check the error messages above and try again.")