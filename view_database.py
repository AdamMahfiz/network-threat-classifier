#!/usr/bin/env python3
"""
Database Content Viewer
Displays the contents of all tables in the threat classifier database
"""

import os
import sys
from datetime import datetime
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from tabulate import tabulate
import pandas as pd

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import User, Role, AnalysisSession, LogEntry, ThreatEvent

def get_table_info():
    """Get information about all tables in the database"""
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    
    print("🗄️  DATABASE OVERVIEW")
    print("=" * 50)
    print(f"Database Engine: {db.engine.url}")
    print(f"Total Tables: {len(tables)}")
    print(f"Tables: {', '.join(tables)}")
    print()
    
    return tables

def view_users():
    """Display all users"""
    print("👥 USERS TABLE")
    print("-" * 30)
    
    try:
        session = db.get_session()
        users = session.query(User).all()
        
        if not users:
            print("No users found.")
            return
        
        user_data = []
        for user in users:
            user_data.append([
                user.id,
                user.username,
                user.email,
                user.first_name or "N/A",
                user.last_name or "N/A",
                "Yes" if user.is_active else "No",
                user.created_at.strftime("%Y-%m-%d %H:%M") if user.created_at else "N/A",
                user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "Never",
                "Yes" if user.totp_secret else "No"
            ])
        
        headers = ["ID", "Username", "Email", "First Name", "Last Name", "Active", "Created", "Last Login", "2FA"]
        print(tabulate(user_data, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error viewing users: {e}")
    finally:
        session.close()

def view_roles():
    """Display all roles"""
    print("\n🔐 ROLES TABLE")
    print("-" * 30)
    
    try:
        session = db.get_session()
        roles = session.query(Role).all()
        
        if not roles:
            print("No roles found.")
            return
        
        role_data = []
        for role in roles:
            role_data.append([
                role.id,
                role.name,
                role.description or "N/A"
            ])
        
        headers = ["ID", "Name", "Description"]
        print(tabulate(role_data, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error viewing roles: {e}")
    finally:
        session.close()

def view_analysis_sessions():
    """Display analysis sessions"""
    print("\n📊 ANALYSIS SESSIONS TABLE")
    print("-" * 40)
    
    try:
        session = db.get_session()
        sessions = session.query(AnalysisSession).all()
        
        if not sessions:
            print("No analysis sessions found.")
            return
        
        session_data = []
        for sess in sessions:
            session_data.append([
                sess.id,
                sess.session_id[:8] + "..." if sess.session_id else "N/A",
                sess.start_time.strftime("%Y-%m-%d %H:%M") if sess.start_time else "N/A",
                sess.end_time.strftime("%Y-%m-%d %H:%M") if sess.end_time else "Ongoing",
                sess.total_records or 0,
                sess.analysis_type or "N/A",
                sess.user_id or "N/A"
            ])
        
        headers = ["ID", "Session ID", "Start Time", "End Time", "Records", "Type", "User ID"]
        print(tabulate(session_data, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error viewing analysis sessions: {e}")
    finally:
        session.close()

def view_log_entries(limit=10):
    """Display recent log entries"""
    print(f"\n📝 LOG ENTRIES TABLE (Last {limit})")
    print("-" * 40)
    
    try:
        session = db.get_session()
        logs = session.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(limit).all()
        
        if not logs:
            print("No log entries found.")
            return
        
        log_data = []
        for log in logs:
            log_data.append([
                log.id,
                log.session_id[:8] + "..." if log.session_id else "N/A",
                log.log_text[:50] + "..." if log.log_text and len(log.log_text) > 50 else log.log_text or "N/A",
                log.threat_level or "N/A",
                f"{log.confidence:.2f}" if log.confidence else "N/A",
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "N/A"
            ])
        
        headers = ["ID", "Session", "Log Text", "Threat Level", "Confidence", "Timestamp"]
        print(tabulate(log_data, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error viewing log entries: {e}")
    finally:
        session.close()

def view_threat_events(limit=10):
    """Display recent threat events"""
    print(f"\n⚠️  THREAT EVENTS TABLE (Last {limit})")
    print("-" * 40)
    
    try:
        session = db.get_session()
        events = session.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc()).limit(limit).all()
        
        if not events:
            print("No threat events found.")
            return
        
        event_data = []
        for event in events:
            event_data.append([
                event.id,
                event.session_id[:8] + "..." if event.session_id else "N/A",
                event.event_type or "N/A",
                str(event.event_details)[:30] + "..." if event.event_details else "N/A",
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "N/A"
            ])
        
        headers = ["ID", "Session", "Event Type", "Details", "Timestamp"]
        print(tabulate(event_data, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error viewing threat events: {e}")
    finally:
        session.close()

def view_table_counts():
    """Display record counts for all tables"""
    print("\n📈 TABLE RECORD COUNTS")
    print("-" * 30)
    
    try:
        session = db.get_session()
        
        counts = [
            ["Users", session.query(User).count()],
            ["Roles", session.query(Role).count()],
            ["Analysis Sessions", session.query(AnalysisSession).count()],
            ["Log Entries", session.query(LogEntry).count()],
            ["Threat Events", session.query(ThreatEvent).count()]
        ]
        
        headers = ["Table", "Record Count"]
        print(tabulate(counts, headers=headers, tablefmt="grid"))
        
    except Exception as e:
        print(f"Error getting table counts: {e}")
    finally:
        session.close()

def export_to_csv():
    """Export all data to CSV files"""
    print("\n💾 EXPORTING DATA TO CSV")
    print("-" * 30)
    
    try:
        session = db.get_session()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export users
        users_df = pd.read_sql_query("SELECT * FROM users", db.engine)
        users_file = f"users_export_{timestamp}.csv"
        users_df.to_csv(users_file, index=False)
        print(f"✅ Users exported to: {users_file}")
        
        # Export analysis sessions
        sessions_df = pd.read_sql_query("SELECT * FROM analysis_sessions", db.engine)
        sessions_file = f"analysis_sessions_export_{timestamp}.csv"
        sessions_df.to_csv(sessions_file, index=False)
        print(f"✅ Analysis sessions exported to: {sessions_file}")
        
        # Export log entries
        logs_df = pd.read_sql_query("SELECT * FROM log_entries", db.engine)
        logs_file = f"log_entries_export_{timestamp}.csv"
        logs_df.to_csv(logs_file, index=False)
        print(f"✅ Log entries exported to: {logs_file}")
        
        # Export threat events
        events_df = pd.read_sql_query("SELECT * FROM threat_events", db.engine)
        events_file = f"threat_events_export_{timestamp}.csv"
        events_df.to_csv(events_file, index=False)
        print(f"✅ Threat events exported to: {events_file}")
        
    except Exception as e:
        print(f"Error exporting data: {e}")

def main():
    """Main function to display database content"""
    print("🔍 NETWORK THREAT CLASSIFIER - DATABASE VIEWER")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Get table information
        get_table_info()
        
        # Display table counts
        view_table_counts()
        
        # Display table contents
        view_users()
        view_roles()
        view_analysis_sessions()
        view_log_entries()
        view_threat_events()
        
        # Ask if user wants to export
        print("\n" + "=" * 60)
        export_choice = input("Would you like to export all data to CSV files? (y/n): ").lower().strip()
        if export_choice in ['y', 'yes']:
            export_to_csv()
        
    except Exception as e:
        print(f"❌ Error accessing database: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure the Flask app is running")
        print("2. Check if the database file exists")
        print("3. Verify database connection settings")

if __name__ == "__main__":
    main()