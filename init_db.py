#!/usr/bin/env python3
"""
Database initialization script for Network Threat Classifier
This script creates all database tables and sets up an initial admin user.
"""

import os
import sys
from getpass import getpass

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import User, Role, Base
from src.threat_classifier.auth.auth_manager import AuthManager

def init_database():
    """Initialize the database with tables and default data."""
    print("Initializing database...")
    
    with app.app_context():
        # Create all tables
        Base.metadata.create_all(bind=db.engine)
        print("✓ Database tables created")
        
        # Get database session
        session = db.get_session()
        
        try:
            # Create default roles
            admin_role = session.query(Role).filter_by(name='admin').first()
            if not admin_role:
                admin_role = Role(name='admin', description='Administrator role with full access')
                session.add(admin_role)
            
            user_role = session.query(Role).filter_by(name='user').first()
            if not user_role:
                user_role = Role(name='user', description='Standard user role')
                session.add(user_role)
            
            session.commit()
            print("✓ Default roles created")
            
            # Check if admin user already exists
            admin_user = session.query(User).filter_by(username='admin').first()
            if admin_user:
                print("⚠ Admin user already exists")
                return
            
            # Create admin user
            print("\nCreating admin user...")
            username = input("Enter admin username (default: admin): ").strip() or 'admin'
            email = input("Enter admin email: ").strip()
            
            while not email:
                email = input("Email is required. Enter admin email: ").strip()
            
            first_name = input("Enter admin first name (default: Admin): ").strip() or 'Admin'
            last_name = input("Enter admin last name (default: User): ").strip() or 'User'
            
            password = getpass("Enter admin password: ")
            while len(password) < 8:
                print("Password must be at least 8 characters long")
                password = getpass("Enter admin password: ")
            
            confirm_password = getpass("Confirm admin password: ")
            while password != confirm_password:
                print("Passwords do not match")
                password = getpass("Enter admin password: ")
                confirm_password = getpass("Confirm admin password: ")
        
            # Create admin user
            auth_manager = AuthManager()
            success, message = auth_manager.register_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            
            if success:
                admin_user = session.query(User).filter_by(username=username).first()
                admin_user.roles.append(admin_role)
                admin_user.roles.append(user_role)
                session.commit()
                print(f"✓ Admin user '{username}' created successfully")
            else:
                print(f"✗ Failed to create admin user: {message}")
                return
            
            print("\n🎉 Database initialization completed successfully!")
            print(f"You can now log in with username: {username}")
            
        finally:
            session.close()

if __name__ == '__main__':
    try:
        init_database()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
    except Exception as e:
        print(f"\n✗ Error during initialization: {str(e)}")
        sys.exit(1)