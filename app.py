"""
Network Threat Classification System
Main Flask application
"""

import os
import time
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
import logging
from datetime import datetime
from dotenv import load_dotenv
import joblib
from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import AnalysisSession, LogEntry, ThreatEvent
import uuid
from sqlalchemy.orm import joinedload
from reportlab.lib.units import inch
from flask_mail import Mail, Message
import psutil
from scapy.all import sniff
from reportlab.pdfgen import canvas

# Load environment variables
load_dotenv()

# Import our modules
from src.threat_classifier.models.threat_classifier import ThreatClassifier
from src.threat_classifier.data.data_processor import DataProcessor
from src.threat_classifier.utils.logger import setup_logger
from src.threat_classifier.data.nsl_kdd_processor import NSLKDDProcessor

# Initialize Flask app
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Increased to 100MB
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'
mail = Mail(app)

# Enable CORS
CORS(app)

# Setup logging
logger = setup_logger('threat_classifier', 'logs/app.log')

# Initialize components
classifier = ThreatClassifier()
data_processor = DataProcessor()
nsl_kdd_processor = None  # Will be loaded if NSL-KDD model exists

# Load NSL-KDD model if available
if os.path.exists('models/nsl_kdd_model.pkl') and os.path.exists('models/nsl_kdd_processor.pkl'):
    try:
        nsl_kdd_processor = joblib.load('models/nsl_kdd_processor.pkl')
        logger.info("NSL-KDD processor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading NSL-KDD processor: {str(e)}")

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('models', exist_ok=True)

# Initialize database
try:
    from src.threat_classifier.database.init_db import init_database
    init_database()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {str(e)}")

# Load model and scaler
MODEL_PATH = 'models/nsl_kdd_model.pkl'
SCALER_PATH = 'models/scaler.pkl'
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Historical data storage
HISTORICAL_DATA = []
ALERTS = []
TRAFFIC_HISTORY = []

# Thresholds
HIGH_THREAT_LABELS = ['high', 'critical', 'attack', 'dos']
TRAFFIC_ALERT_THRESHOLD = 1000  # packets per minute (example)

# Helper: Send email
def send_email_alert(subject, body):
    try:
        msg = Message(subject, recipients=['recipient@example.com'])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Email send failed: {e}")

# Helper: Generate PDF report
def generate_pdf_report(data, filename):
    c = canvas.Canvas(filename)
    c.drawString(100, 800, "Threat Analysis Report")
    y = 780
    for entry in data[-20:]:
        c.drawString(100, y, str(entry))
        y -= 20
    c.save()

# Threat classification (dummy, replace with real feature extraction)
def classify(features):
    X = scaler.transform([features])
    pred = model.predict(X)[0]
    return pred

# Live traffic monitor (runs in background)
def monitor_traffic():
    global TRAFFIC_HISTORY
    while True:
        count = 0
        def count_packet(pkt):
            nonlocal count
            count += 1
        sniff(timeout=60, prn=count_packet, store=0)
        TRAFFIC_HISTORY.append((datetime.now(), count))
        if count > TRAFFIC_ALERT_THRESHOLD:
            ALERTS.append({'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'type': 'DDoS', 'level': 'critical', 'msg': f'High traffic detected: {count} packets/min'})
            send_email_alert('DDoS Alert', f'High traffic detected: {count} packets/min')

# Start traffic monitor thread
def start_traffic_monitor():
    t = threading.Thread(target=monitor_traffic, daemon=True)
    t.start()

start_traffic_monitor()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('logfile')
        if file:
            df = pd.read_csv(file)
            for _, row in df.iterrows():
                features = row.values.tolist()
                pred = classify(features)
                HISTORICAL_DATA.append({'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'features': features, 'prediction': pred})
                if str(pred).lower() in HIGH_THREAT_LABELS:
                    ALERTS.append({'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'type': 'Threat', 'level': pred, 'msg': f'High threat detected: {pred}'})
                    send_email_alert('High Threat Alert', f'High threat detected: {pred}')
            flash('File processed and threats classified.')
            return redirect(url_for('index'))
    return render_template('index.html', alerts=ALERTS[-10:], trends=HISTORICAL_DATA[-50:])

@app.route('/health')
def health():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    }

@app.route('/api/classify', methods=['POST'])
def classify_logs():
    """Classify log entries"""
    try:
        data = request.get_json()
        if not data or 'logs' not in data:
            return jsonify({'error': 'No log data provided'}), 400
        
        # Create new analysis session
        session_id = str(uuid.uuid4())
        db_session = db.get_session()
        analysis_session = AnalysisSession(
            session_id=session_id,
            analysis_type='text_input',
            start_time=datetime.utcnow()
        )
        db_session.add(analysis_session)
        db_session.commit()  # Commit the session to the database
        
        # Log threat event
        threat_event = ThreatEvent(
            session_id=session_id,
            event_type='analysis_start',
            event_details={'input_type': 'text_input'}
        )
        db_session.add(threat_event)
        
        logs = data['logs'].strip().split('\n')
        logs = [log.strip() for log in logs if log.strip()]
        
        if not logs:
            return jsonify({'error': 'No valid log entries found'}), 400
        
        logger.info(f"Processing {len(logs)} logs")
        
        # Check if it's NSL-KDD format
        is_nsl_kdd = False
        if len(logs) > 0:
            first_line = logs[0].split(',')
            if len(first_line) >= 41:
                is_nsl_kdd = True
        
        if is_nsl_kdd and nsl_kdd_processor:
            # Process as NSL-KDD data
            split_lines = [log.split(',') for log in logs]
            if len(split_lines[0]) == 43:
                split_lines = [cols[:-1] for cols in split_lines]
            df = pd.DataFrame(split_lines, columns=nsl_kdd_processor.feature_names + ['label'])
            features = nsl_kdd_processor.transform(df)
            
            if os.path.exists('models/nsl_kdd_model.pkl'):
                nsl_kdd_model = joblib.load('models/nsl_kdd_model.pkl')
                predictions = nsl_kdd_model.predict(features)
                probabilities = nsl_kdd_model.predict_proba(features)
            else:
                logger.warning("NSL-KDD model not found, falling back to regular classifier")
                predictions = classifier.predict(features)
                probabilities = classifier.predict_proba(features)
        else:
            processed_logs = data_processor.process_logs(logs)
            predictions = classifier.predict(processed_logs)
            probabilities = classifier.predict_proba(processed_logs)
        
        # Prepare results
        threat_levels = ['Low', 'Medium', 'High']
        threat_dist = {
            'Low': int(np.sum(predictions == 0)),
            'Medium': int(np.sum(predictions == 1)),
            'High': int(np.sum(predictions == 2))
        }
        
        # Generate visualization
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_path = os.path.join('static', 'reports', f'threat_analysis_{timestamp}.pdf')
        os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
        
        # Create PDF with visualizations
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.piecharts import Pie
        
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph("Network Threat Analysis Report", title_style))
        story.append(Spacer(1, 20))
        
        # Calculate percentages for pie chart
        total = sum(threat_dist.values())
        percentages = {
            level: (count / total) * 100 
            for level, count in threat_dist.items()
        }
        
        # Create pie chart
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 100
        pie.y = 0
        pie.width = 200
        pie.height = 200
        pie.data = [threat_dist[level] for level in threat_levels]
        pie.labels = [f"{level}\n({percentages[level]:.1f}%)" for level in threat_levels]
        pie.slices.strokeWidth = 0.5
        
        # Set colors for each slice
        pie.slices[0].fillColor = colors.green  # Low threat - green
        pie.slices[1].fillColor = colors.yellow  # Medium threat - yellow
        pie.slices[2].fillColor = colors.red  # High threat - red
        
        drawing.add(pie)
        story.append(drawing)
        story.append(Spacer(1, 20))
        
        # Sample of 10 logs with their classifications
        story.append(Paragraph("Sample Analysis (10 Logs)", styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Create table for sample logs
        sample_data = [['Log', 'Threat Level', 'Confidence']]
        for i, (log, pred, prob) in enumerate(zip(logs[:10], predictions[:10], probabilities[:10])):
            threat_level = threat_levels[int(pred)]
            confidence = float(prob.max())
            
            # Store log entry in database
            log_entry = LogEntry(
                session_id=session_id,
                log_text=str(log)[:1000],  # Truncate if too long
                threat_level=threat_level,
                confidence=confidence
            )
            db_session.add(log_entry)
            
            sample_data.append([
                str(log)[:60] + '...' if len(str(log)) > 60 else str(log),
                threat_level,
                f"{confidence:.2%}"
            ])
        
        table = Table(sample_data, colWidths=[3.5*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 3),
            ('WORDWRAP', (0, 0), (0, -1), True),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(table)
        
        # Build PDF
        doc.build(story)
        
        # Update analysis session
        analysis_session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
        if analysis_session:
            analysis_session.end_time = datetime.utcnow()
            analysis_session.total_records = len(logs)
            analysis_session.threat_distribution = threat_dist
            analysis_session.report_path = pdf_path
        else:
            logger.error(f"Analysis session {session_id} not found.")
            return jsonify({'error': 'Analysis session not found'}), 404
        
        # Log completion event
        completion_event = ThreatEvent(
            session_id=session_id,
            event_type='analysis_complete',
            event_details={
                'total_records': len(logs),
                'threat_distribution': threat_dist,
                'report_path': pdf_path
            }
        )
        db_session.add(completion_event)
        
        # Commit all database changes
        db_session.commit()
        
        # Prepare response
        results = {
            'total_logs': len(logs),
            'sample_classifications': [
                {
                    'log': str(log),
                    'threat_level': threat_levels[int(pred)],
                    'confidence': float(prob.max())
                }
                for log, pred, prob in zip(logs[:10], predictions[:10], probabilities[:10])
            ],
            'threat_distribution': threat_dist,
            'timestamp': datetime.now().isoformat(),
            'report_path': pdf_path,
            'session_id': session_id
        }
        
        logger.info("Classification completed successfully")
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error classifying logs: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        if 'db_session' in locals():
            db_session.rollback()
        return jsonify({'error': f'Classification error: {str(e)}'}), 500
    finally:
        if 'db_session' in locals():
            db_session.close()

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload with better error handling"""
    try:
        logger.info("File upload request received")
        
        if 'file' not in request.files:
            logger.warning("No file in request")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("Empty filename")
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            logger.info(f"Saving file to: {filepath}")
            file.save(filepath)
            
            # Create new analysis session
            session_id = str(uuid.uuid4())
            db_session = db.get_session()
            analysis_session = AnalysisSession(
                session_id=session_id,
                analysis_type='file_upload',
                start_time=datetime.utcnow()
            )
            db_session.add(analysis_session)
            db_session.commit()  # Commit the session to the database
            
            # Log file upload event
            upload_event = ThreatEvent(
                session_id=session_id,
                event_type='file_upload',
                event_details={
                    'filename': filename,
                    'filepath': filepath
                }
            )
            db_session.add(upload_event)
            
            # Process the file
            results = process_uploaded_file(filepath, session_id, db_session)
            
            # Clean up
            try:
                os.remove(filepath)
                logger.info("Temporary file cleaned up")
            except:
                pass
            
            logger.info("File processing completed successfully")
            return jsonify(results)
        
        return jsonify({'error': 'Invalid file type. Please use .txt, .csv, or .log files'}), 400
        
    except Exception as e:
        logger.error(f"Error processing upload: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        if 'db_session' in locals():
            db_session.rollback()
        return jsonify({'error': f'Upload processing error: {str(e)}'}), 500
    finally:
        if 'db_session' in locals():
            db_session.close()

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'log'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_uploaded_file(filepath, session_id, db_session):
    """Process uploaded file with better error handling and NSL-KDD support"""
    try:
        logger.info(f"Processing uploaded file: {filepath}")
        
        # Read file lines
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            logs = f.readlines()
        logs = [log.strip() for log in logs if log.strip()]
        logger.info(f"Text file loaded with {len(logs)} lines")

        # Check if it's NSL-KDD format
        is_nsl_kdd = False
        if len(logs) > 0:
            first_line = logs[0].split(',')
            if len(first_line) >= 41:
                is_nsl_kdd = True
        
        if is_nsl_kdd and nsl_kdd_processor:
            # Process as NSL-KDD data
            split_lines = [log.split(',') for log in logs]
            if len(split_lines[0]) == 43:
                split_lines = [cols[:-1] for cols in split_lines]
            df = pd.DataFrame(split_lines, columns=nsl_kdd_processor.feature_names + ['label'])
            features = nsl_kdd_processor.transform(df)
            
            if os.path.exists('models/nsl_kdd_model.pkl'):
                nsl_kdd_model = joblib.load('models/nsl_kdd_model.pkl')
                predictions = nsl_kdd_model.predict(features)
                probabilities = nsl_kdd_model.predict_proba(features)
            else:
                logger.warning("NSL-KDD model not found, falling back to regular classifier")
                predictions = classifier.predict(features)
                probabilities = classifier.predict_proba(features)
        else:
            processed_data = data_processor.process_logs(logs)
            predictions = classifier.predict(processed_data)
            probabilities = classifier.predict_proba(processed_data)

        # Generate simplified PDF report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_path = os.path.join('static', 'reports', f'report_{timestamp}.pdf')
        os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.piecharts import Pie

        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12
        )
        story.append(Paragraph("Threat Analysis Report", title_style))
        story.append(Spacer(1, 12))

        # Summary
        threat_dist = {
            'Low': int(np.sum(predictions == 0)),
            'Medium': int(np.sum(predictions == 1)),
            'High': int(np.sum(predictions == 2))
        }
        
        # Calculate percentages for pie chart
        total = sum(threat_dist.values())
        percentages = {
            level: (count / total) * 100 
            for level, count in threat_dist.items()
        }
        
        # Add pie chart
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 100
        pie.y = 0
        pie.width = 200
        pie.height = 200
        pie.data = [threat_dist[level] for level in ['Low', 'Medium', 'High']]
        pie.labels = [f"{level}\n({percentages[level]:.1f}%)" for level in ['Low', 'Medium', 'High']]
        pie.slices.strokeWidth = 0.5
        
        # Set colors for each slice
        pie.slices[0].fillColor = colors.green  # Low threat - green
        pie.slices[1].fillColor = colors.yellow  # Medium threat - yellow
        pie.slices[2].fillColor = colors.red  # High threat - red
        
        drawing.add(pie)
        story.append(drawing)
        story.append(Spacer(1, 20))
        
        summary_data = [
            ['Total Logs', str(len(logs))],
            ['Low Threat', str(threat_dist['Low'])],
            ['Medium Threat', str(threat_dist['Medium'])],
            ['High Threat', str(threat_dist['High'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

        # Sample logs table
        story.append(Paragraph("Sample Analysis", styles['Heading2']))
        story.append(Spacer(1, 6))

        sample_data = [['Log', 'Threat', 'Confidence']]
        for i, (log, pred, prob) in enumerate(zip(logs[:10], predictions[:10], probabilities[:10])):
            threat_level = ['Low', 'Medium', 'High'][int(pred)]
            confidence = float(prob.max())
            
            # Store log entry in database
            log_entry = LogEntry(
                session_id=session_id,
                log_text=str(log)[:1000],  # Truncate if too long
                threat_level=threat_level,
                confidence=confidence
            )
            db_session.add(log_entry)
            
            sample_data.append([
                str(log)[:60] + '...' if len(str(log)) > 60 else str(log),
                threat_level,
                f"{confidence:.1%}"
            ])

        sample_table = Table(sample_data, colWidths=[3.5*inch, 1*inch, 1*inch])
        sample_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 3),
            ('WORDWRAP', (0, 0), (0, -1), True),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(sample_table)

        # Build PDF
        doc.build(story)

        # Update analysis session
        analysis_session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
        if analysis_session:
            analysis_session.end_time = datetime.utcnow()
            analysis_session.total_records = len(logs)
            analysis_session.threat_distribution = threat_dist
            analysis_session.report_path = pdf_path
        else:
            logger.error(f"Analysis session {session_id} not found.")
            return jsonify({'error': 'Analysis session not found'}), 404
        
        # Log completion event
        completion_event = ThreatEvent(
            session_id=session_id,
            event_type='analysis_complete',
            event_details={
                'total_records': len(logs),
                'threat_distribution': threat_dist,
                'report_path': pdf_path
            }
        )
        db_session.add(completion_event)
        
        # Commit all database changes
        db_session.commit()

        return {
            'total_records': len(predictions),
            'threat_distribution': threat_dist,
            'timestamp': datetime.now().isoformat(),
            'report_path': pdf_path,
            'session_id': session_id,
            'sample_classifications': [
                {
                    'log': str(log),
                    'threat_level': ['Low', 'Medium', 'High'][int(pred)],
                    'confidence': float(prob.max())
                }
                for log, pred, prob in zip(logs[:10], predictions[:10], probabilities[:10])
            ]
        }
    except Exception as e:
        logger.error(f"Error in process_uploaded_file: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise e

@app.route('/api/audit/sessions', methods=['GET'])
def get_sessions():
    """Return a list of all analysis sessions (most recent first)"""
    db_session = db.get_session()
    try:
        sessions = db_session.query(AnalysisSession).order_by(AnalysisSession.start_time.desc()).all()
        result = []
        for s in sessions:
            result.append({
                'session_id': s.session_id,
                'start_time': s.start_time.isoformat() if s.start_time else None,
                'end_time': s.end_time.isoformat() if s.end_time else None,
                'total_records': s.total_records,
                'threat_distribution': s.threat_distribution,
                'report_path': s.report_path,
                'analysis_type': s.analysis_type
            })
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fetching sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        db_session.close()

@app.route('/api/audit/session/<session_id>', methods=['GET'])
def get_session_details(session_id):
    """Return details, logs, and events for a specific session"""
    db_session = db.get_session()
    try:
        session = db_session.query(AnalysisSession).options(
            joinedload(AnalysisSession.log_entries),
            joinedload(AnalysisSession.threat_events)
        ).filter_by(session_id=session_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        result = {
            'session_id': session.session_id,
            'start_time': session.start_time.isoformat() if session.start_time else None,
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'total_records': session.total_records,
            'threat_distribution': session.threat_distribution,
            'report_path': session.report_path,
            'analysis_type': session.analysis_type,
            'logs': [
                {
                    'log_text': log.log_text,
                    'threat_level': log.threat_level,
                    'confidence': log.confidence,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None
                }
                for log in session.log_entries
            ],
            'events': [
                {
                    'event_type': event.event_type,
                    'event_details': event.event_details,
                    'timestamp': event.timestamp.isoformat() if event.timestamp else None
                }
                for event in session.threat_events
            ]
        }
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fetching session details: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        db_session.close()

@app.route('/audit')
def audit_page():
    return render_template('audit.html')

@app.route('/download_report')
def download_report():
    filename = f'static/reports/report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    generate_pdf_report(HISTORICAL_DATA, filename)
    return send_file(filename, as_attachment=True)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(ALERTS[-20:])

@app.route('/api/trends')
def api_trends():
    return jsonify(HISTORICAL_DATA[-50:])

if __name__ == '__main__':
    # Train model if not already trained
    if not classifier.is_trained():
        logger.info("Training initial model...")
        classifier.train()
        logger.info("Model training completed")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
