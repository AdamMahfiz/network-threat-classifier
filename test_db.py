from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import AnalysisSession, LogEntry, ThreatEvent
from datetime import datetime
import uuid

def test_database_connection():
    try:
        # Get a database session
        session = db.get_session()
        print("✅ Successfully connected to the database")
        
        # Create a test analysis session
        session_id = str(uuid.uuid4())
        test_session = AnalysisSession(
            session_id=session_id,
            analysis_type='test',
            start_time=datetime.utcnow(),
            total_records=0,
            threat_distribution={'Low': 0, 'Medium': 0, 'High': 0}
        )
        session.add(test_session)
        
        # Create a test log entry
        test_log = LogEntry(
            session_id=session_id,
            log_text="Test log entry",
            threat_level="Low",
            confidence=0.95
        )
        session.add(test_log)
        
        # Create a test threat event
        test_event = ThreatEvent(
            session_id=session_id,
            event_type='test',
            event_details={'test': True}
        )
        session.add(test_event)
        
        # Commit the changes
        session.commit()
        print("✅ Successfully created test records")
        
        # Query the test records
        analysis = session.query(AnalysisSession).filter_by(session_id=session_id).first()
        log = session.query(LogEntry).filter_by(session_id=session_id).first()
        event = session.query(ThreatEvent).filter_by(session_id=session_id).first()
        
        print("\nTest Records:")
        print(f"Analysis Session: {analysis.session_id}")
        print(f"Log Entry: {log.log_text} - {log.threat_level}")
        print(f"Threat Event: {event.event_type}")
        
        # Clean up test records
        session.delete(log)
        session.delete(event)
        session.delete(analysis)
        session.commit()
        print("\n✅ Successfully cleaned up test records")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing database connection: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False
    finally:
        if 'session' in locals():
            session.close()

if __name__ == "__main__":
    print("Testing database connection...")
    test_database_connection() 