"""
Network Threat Classification System
Main Flask application
"""

import os
import time
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, jsonify, session
from flask_cors import CORS
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
import joblib
from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import AnalysisSession, LogEntry, ThreatEvent, User
import uuid
from sqlalchemy.orm import joinedload
from reportlab.lib.units import inch
from flask_mail import Mail, Message
import psutil
from scapy.all import sniff
from reportlab.pdfgen import canvas
from flask_socketio import SocketIO, emit
from sqlalchemy import text
from flask_login import LoginManager, current_user, login_required, logout_user

# Import the new threat detection system
try:
    from src.threat_classifier.utils.threat_settings import get_threat_tracker
    ADVANCED_THREAT_DETECTION = True
    print("✅ Advanced threat detection system loaded")
except ImportError as e:
    print(f"⚠️ Advanced threat detection not available: {e}")
    ADVANCED_THREAT_DETECTION = False

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

# Disable caching for development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Session timeout configuration (30 minutes of inactivity)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_TIMEOUT'] = 30 * 60  # 30 minutes in seconds
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///threat_classifier.db')

print("MAIL_SERVER:", app.config['MAIL_SERVER'])
print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
print("MAIL_DEFAULT_SENDER:", app.config['MAIL_DEFAULT_SENDER'])

mail = Mail(app)

# Initialize SocketIO with better compatibility settings
socketio = SocketIO(app, 
                   async_mode='threading',
                   cors_allowed_origins="*",
                   logger=True,
                   engineio_logger=True,
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=2000000,
                   always_connect=True,
                   compression=False,
                   allow_upgrades=True,
                   transports=['websocket', 'polling'])

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

# Register blueprints
from src.threat_classifier.auth.routes import auth_bp
from src.threat_classifier.auth.auth_manager import login_manager

# Initialize Flask-Login with the auth manager
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('auth.unauthorized'))

# Session timeout handler
@app.before_request
def check_session_timeout():
    """Check if user session has expired due to inactivity"""
    # Skip timeout check for auth routes, static files, API routes, and download routes
    if (request.endpoint and 
        (request.endpoint.startswith('auth.') or 
         request.endpoint.startswith('static') or
         request.path.startswith('/api/') or
         request.path.startswith('/socket.io') or
         request.endpoint in ['unauthorized', 'download_report'])):
        return
    
    if current_user.is_authenticated:
        # Check if session has last_activity timestamp
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            timeout_duration = timedelta(seconds=app.config['SESSION_TIMEOUT'])
            
            if datetime.now() - last_activity > timeout_duration:
                # Session has expired
                logout_user()
                session.clear()
                flash('Your session has expired due to inactivity. Please log in again.', 'warning')
                return redirect(url_for('auth.login'))
        
        # Update last activity timestamp
        session['last_activity'] = datetime.now().isoformat()
        session.permanent = True

app.register_blueprint(auth_bp, url_prefix='/auth')

# Load model and scaler with error handling
MODEL_PATH = 'models/nsl_kdd_model.pkl'
SCALER_PATH = 'models/scaler.pkl'

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    logger.info("Model and scaler loaded successfully")
except FileNotFoundError as e:
    logger.error(f"Model files not found: {str(e)}")
    model = None
    scaler = None
except Exception as e:
    logger.error(f"Error loading model/scaler: {str(e)}")
    model = None
    scaler = None

# Historical data storage
HISTORICAL_DATA = []
ALERTS = []
TRAFFIC_HISTORY = []
LIVE_MONITORING_ENABLED = False
monitor_thread = None

# Email alerts config
EMAIL_ALERTS_ENABLED = os.environ.get('EMAIL_ALERTS_ENABLED', 'True') == 'True'
EMAIL_ALERT_COOLDOWN_SECONDS = int(os.environ.get('EMAIL_ALERT_COOLDOWN_SECONDS', 120))
last_email_alert_ts = 0

# Thresholds
HIGH_THREAT_LABELS = ['high', 'critical', 'attack', 'dos']
TRAFFIC_ALERT_THRESHOLD = 50  # packets per 5sec interval (lowered for demo)

# Helper: Send email
# For Gmail, set in .env:
# MAIL_SERVER=smtp.gmail.com
# MAIL_PORT=587
# MAIL_USE_TLS=True
# MAIL_USERNAME=your_email@gmail.com
# MAIL_PASSWORD=your_app_password
# MAIL_DEFAULT_SENDER=your_email@gmail.com
def send_email_alert(subject, body, high_count=None, timestamp=None, severity=None, messages=None):
    try:
        with app.app_context():
            # Guard: ensure mail is configured and enabled
            if not EMAIL_ALERTS_ENABLED:
                logger.info("Email alerts disabled via config; skipping send.")
                return False
            if not app.config.get('MAIL_SERVER'):
                logger.warning("MAIL_SERVER not configured; cannot send email alert.")
                return False
            admin_email = app.config.get('MAIL_DEFAULT_SENDER') or 'admin@example.com'
            # Recipients: default to sender; allow overrides via env ALERT_RECIPIENTS
            recipient_env = os.environ.get('ALERT_RECIPIENTS', '')
            recipients = [r.strip() for r in recipient_env.split(',') if r.strip()] or [admin_email]
            # Build vibrant HTML using template
            dashboard_url = os.environ.get('APP_BASE_URL', 'http://localhost:5000/')

            # Auto-format classification summary subject/body when provided
            if high_count is not None and timestamp is not None:
                subject = f"[Network Threat Classifier] High Threat Alert: {high_count} Detected"
                intro_text = (
                    "A new analysis completed and detected multiple high-level threats. "
                    "Review the details below and take appropriate action."
                )
            else:
                intro_text = body or "An alert has been generated by the Network Threat Classifier."

            # Render HTML email
            html = render_template(
                'email/alert.html',
                subject=subject,
                intro_text=intro_text,
                severity=severity,
                messages=messages or [],
                high_count=high_count,
                timestamp=timestamp,
                dashboard_url=dashboard_url,
            )

            # Prepare message with both HTML and plaintext fallback
            msg = Message(subject, recipients=recipients)
            msg.body = (body or intro_text)
            msg.html = html
            mail.send(msg)
            return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False

# Helper: Maybe send email alert for live traffic (rate-limited)
def maybe_send_email_live_alert(threat_level, alert_messages):
    try:
        global last_email_alert_ts
        if not EMAIL_ALERTS_ENABLED:
            return False
        if threat_level not in ['medium', 'high']:
            return False
        now_ts = time.time()
        if (now_ts - last_email_alert_ts) < EMAIL_ALERT_COOLDOWN_SECONDS:
            return False
        subject = f"[Network Threat Classifier] {threat_level.title()} Network Alert"
        # Delegate HTML formatting to send_email_alert
        sent = send_email_alert(
            subject,
            body=None,
            high_count=None,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            severity=threat_level,
            messages=alert_messages,
        )
        if sent:
            last_email_alert_ts = now_ts
        return sent
    except Exception as e:
        logger.error(f"maybe_send_email_live_alert error: {e}")
        return False

# Helper: Generate PDF report
def generate_pdf_report(data, filename):
    c = canvas.Canvas(filename)
    c.drawString(100, 800, "Threat Analysis Report")
    y = 780
    for entry in data[-20:]:
        c.drawString(100, y, str(entry))
        y -= 20
    c.save()

# Threat classification with proper feature handling
def classify(features):
    try:
        # Check if model and scaler are available
        if model is None or scaler is None:
            logger.warning("Model or scaler not available, returning default prediction")
            return 'normal'
            
        # Convert features to numeric, handling strings
        numeric_features = []
        for feature in features:
            try:
                numeric_features.append(float(feature))
            except (ValueError, TypeError):
                # For categorical features, use a simple hash or default value
                numeric_features.append(hash(str(feature)) % 1000)
        
        X = scaler.transform([numeric_features])
        pred = model.predict(X)[0]
        return pred
    except Exception as e:
        logger.error(f"Classification error: {e}")
        # Return a default prediction if classification fails
        return 'normal'

def get_threat_class(pred):
    pred_str = str(pred).lower()
    
    # Handle numerical predictions (0=normal, 1=medium, 2=high)
    if pred_str in ['0', 'normal', 'benign']:
        return 'low'
    elif pred_str in ['1', 'medium']:
        return 'medium'
    elif pred_str in ['2', 'high', 'critical', 'attack', 'dos', 'probe', 'r2l', 'u2r']:
        return 'high'
    
    # Handle specific attack types
    attack_types = ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'udpstorm', 'processtable', 'worm', 'httptunnel', 'ps', 'sqlattack', 'buffer_overflow', 'loadmodule', 'rootkit', 'perl', 'xterm', 'guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 'warezclient', 'spy', 'portsweep', 'ipsweep', 'nmap', 'satan', 'mscan', 'saint']
    
    if pred_str in attack_types:
        return 'high'
    
    # Default to low if we can't determine
    return 'low'

# Real-time network traffic monitor using packet capture
def monitor_traffic():
    global TRAFFIC_HISTORY
    import time
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    
    logger.info("Starting real-time network traffic monitoring")
    
    # Packet capture statistics
    packet_count = 0
    capture_start_time = time.time()
    update_counter = 0
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    # Packet analysis data
    protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
    packet_sizes = []
    suspicious_patterns = []
    
    def analyze_packet(pkt):
        nonlocal packet_count, protocol_counts, packet_sizes, suspicious_patterns
        
        try:
            packet_count += 1
            
            # Analyze packet size
            packet_size = len(pkt)
            packet_sizes.append(packet_size)
            
            # Keep only recent packet sizes for performance
            if len(packet_sizes) > 1000:
                packet_sizes = packet_sizes[-500:]
            
            # Protocol analysis
            if IP in pkt:
                if TCP in pkt:
                    protocol_counts['TCP'] += 1
                    # Check for potential port scanning
                    if pkt[TCP].flags == 2:  # SYN flag only
                        suspicious_patterns.append({
                            'type': 'port_scan',
                            'src': pkt[IP].src,
                            'dst': pkt[IP].dst,
                            'port': pkt[TCP].dport,
                            'time': time.time()
                        })
                elif UDP in pkt:
                    protocol_counts['UDP'] += 1
                elif ICMP in pkt:
                    protocol_counts['ICMP'] += 1
                    # Check for potential ICMP flood
                    if pkt[ICMP].type == 8:  # Echo request
                        suspicious_patterns.append({
                            'type': 'icmp_flood',
                            'src': pkt[IP].src,
                            'dst': pkt[IP].dst,
                            'time': time.time()
                        })
                else:
                    protocol_counts['Other'] += 1
            
            # Clean old suspicious patterns (keep only last 60 seconds)
            current_time = time.time()
            suspicious_patterns[:] = [p for p in suspicious_patterns if current_time - p['time'] < 60]
            
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
    
    try:
        while LIVE_MONITORING_ENABLED:
            try:
                # Reset counters for this capture period
                packet_count = 0
                protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
                capture_start_time = time.time()
                
                logger.info("Starting 5-second packet capture...")
                
                # Capture packets for 5 seconds
                try:
                    sniff(timeout=5, prn=analyze_packet, store=0)
                except Exception as capture_error:
                    logger.warning(f"Packet capture error: {capture_error}")
                    # Fall back to simulated data if capture fails
                    packet_count = 10 + (update_counter % 20)  # Simulate some activity
                
                capture_duration = time.time() - capture_start_time
                
                # Calculate metrics
                packets_per_second = packet_count / max(capture_duration, 1)
                avg_packet_size = sum(packet_sizes[-packet_count:]) / max(packet_count, 1) if packet_sizes else 64
                
                # Add to history
                TRAFFIC_HISTORY.append({
                    'time': datetime.now(), 
                    'count': packet_count,
                    'packets_per_second': packets_per_second,
                    'protocols': protocol_counts.copy(),
                    'avg_size': avg_packet_size
                })
                
                if len(TRAFFIC_HISTORY) > 100:
                    TRAFFIC_HISTORY.pop(0)
                
                # Threat detection using new advanced system
                if ADVANCED_THREAT_DETECTION:
                    # Use the new advanced threat detection system
                    threat_tracker = get_threat_tracker()
                    threat_level = threat_tracker.evaluate_threat_level(packets_per_second)
                    
                    # Get statistics for additional context
                    stats = threat_tracker.get_statistics()
                    
                    # Generate alert messages based on threat level
                    alert_messages = []
                    if threat_level == 'high':
                        alert_messages.append(f'High threat detected: {packets_per_second:.1f} pps (avg: {stats["avg_pps"]} pps)')
                        if stats['escalations'] > 0:
                            alert_messages.append(f'Threat escalated due to sustained/burst patterns')
                    elif threat_level == 'medium':
                        alert_messages.append(f'Medium threat detected: {packets_per_second:.1f} pps')
                    elif threat_level == 'low':
                        alert_messages.append(f'Low threat detected: {packets_per_second:.1f} pps')
                    
                else:
                    # Fallback to legacy threat detection
                    threat_level = 'normal'
                    alert_messages = []
                    
                    # High packet rate detection (increased threshold for video streaming)
                    if packets_per_second > 500:  # Increased from 100 to 500 for video streaming
                        threat_level = 'high'
                        alert_messages.append(f'Extremely high packet rate: {packets_per_second:.1f} pps')
                    elif packets_per_second > 250:  # Medium threat for moderately high traffic
                        threat_level = 'medium'
                        alert_messages.append(f'High packet rate: {packets_per_second:.1f} pps')
                
                # Additional pattern detection (still useful for context)
                # Suspicious pattern detection (more lenient for modern web apps)
                recent_port_scans = [p for p in suspicious_patterns if p['type'] == 'port_scan' and time.time() - p['time'] < 10]
                if len(recent_port_scans) > 50:  # Increased from 10 to 50 for multiple connections
                    if not ADVANCED_THREAT_DETECTION:  # Only override if not using advanced system
                        threat_level = 'high'
                    alert_messages.append(f'Potential port scan detected: {len(recent_port_scans)} attempts')
                elif len(recent_port_scans) > 25:  # Medium threat for moderate scanning
                    if not ADVANCED_THREAT_DETECTION and threat_level != 'high':  # Don't downgrade from high
                        threat_level = 'medium'
                    alert_messages.append(f'Suspicious connection pattern: {len(recent_port_scans)} attempts')
                
                recent_icmp_floods = [p for p in suspicious_patterns if p['type'] == 'icmp_flood' and time.time() - p['time'] < 10]
                if len(recent_icmp_floods) > 100:  # Increased from 50 to 100
                    if not ADVANCED_THREAT_DETECTION:
                        threat_level = 'high'
                    alert_messages.append(f'Potential ICMP flood: {len(recent_icmp_floods)} packets')
                elif len(recent_icmp_floods) > 75:  # Medium threat for moderate ICMP
                    if not ADVANCED_THREAT_DETECTION and threat_level != 'high':
                        threat_level = 'medium'
                    alert_messages.append(f'High ICMP activity: {len(recent_icmp_floods)} packets')
                
                # Protocol anomaly detection (more lenient thresholds)
                total_packets = sum(protocol_counts.values())
                if total_packets > 0:
                    icmp_ratio = protocol_counts['ICMP'] / total_packets
                    if icmp_ratio > 0.9 and total_packets > 50:  # Increased thresholds
                        if not ADVANCED_THREAT_DETECTION and threat_level != 'high':
                            threat_level = 'medium'
                        alert_messages.append(f'Very high ICMP ratio: {icmp_ratio:.1%}')
                    elif icmp_ratio > 0.7 and total_packets > 30:  # Lower severity warning
                        # Only add message, don't change threat level for this
                        pass  # Just monitor, don't alert for normal ICMP usage
                
                # Generate alerts for threats
                if threat_level in ['medium', 'high'] and alert_messages:
                    alert = {
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'Network Anomaly',
                        'level': threat_level,
                        'msg': f'🚨 {"; ".join(alert_messages)}'
                    }
                    ALERTS.append(alert)
                    if len(ALERTS) > 50:
                        ALERTS.pop(0)
                    
                    try:
                        alert_log = {**alert, 'msg': alert['msg'].replace('🚨', 'ALERT:')}
                        logger.info(f"Emitting real-time alert: {alert_log}")
                        socketio.emit('live_alert', alert)
                        # Try sending a rate-limited email alert
                        maybe_send_email_live_alert(threat_level, alert_messages)
                        consecutive_errors = 0
                    except Exception as e:
                        consecutive_errors += 1
                        if consecutive_errors <= max_consecutive_errors:
                            logger.warning(f"Error emitting alert (attempt {consecutive_errors}): {e}")
                
                # Emit traffic data
                traffic_data = {
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'count': packet_count,
                    'packets_per_second': round(packets_per_second, 1),
                    'avgPacketSize': round(avg_packet_size),
                    'protocols': protocol_counts,
                    'threatsDetected': len([a for a in ALERTS if a['time'].startswith(datetime.now().strftime('%Y-%m-%d'))]),
                    'status': 'active',
                    'capture_method': 'real-time',
                    'threat_level': threat_level
                }
                
                try:
                    logger.info(f"Real-time update: {packet_count} packets, {packets_per_second:.1f} pps, threat: {threat_level}")
                    socketio.emit('traffic_update', traffic_data)
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    if consecutive_errors <= max_consecutive_errors:
                        logger.warning(f"Error emitting traffic update (attempt {consecutive_errors}): {e}")
                
                # Emit heartbeat every 10 updates
                update_counter += 1
                if update_counter % 10 == 0:
                    try:
                        socketio.emit('monitoring_heartbeat', {
                            'timestamp': datetime.now().isoformat(),
                            'status': 'running',
                            'updates_sent': update_counter,
                            'total_packets': sum(protocol_counts.values())
                        })
                    except Exception as e:
                        logger.warning(f"Error emitting heartbeat: {e}")
                
                # Brief pause between capture cycles
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop iteration: {e}")
                consecutive_errors += 1
                if consecutive_errors > max_consecutive_errors:
                    logger.error(f"Too many consecutive errors ({consecutive_errors}), continuing with reduced logging")
                time.sleep(2)
                
    except Exception as e:
        logger.error(f"Fatal error in monitoring thread: {e}")
    finally:
        logger.info("Real-time traffic monitoring stopped")
        try:
            socketio.emit('monitoring_status', {'enabled': False, 'reason': 'stopped'})
        except:
            pass

def start_traffic_monitor():
    global monitor_thread, LIVE_MONITORING_ENABLED
    logger.info("Attempting to start traffic monitor")
    
    # Enable monitoring flag
    LIVE_MONITORING_ENABLED = True
    
    # Check if thread exists and is alive
    if monitor_thread is None or not monitor_thread.is_alive():
        try:
            # Clean up any dead thread references
            if monitor_thread is not None and not monitor_thread.is_alive():
                monitor_thread = None
            
            # Create and start new thread
            monitor_thread = threading.Thread(target=monitor_traffic, daemon=True, name="TrafficMonitor")
            monitor_thread.start()
            logger.info("Traffic monitor thread started successfully")
            
            # Emit status to connected clients
            socketio.emit('monitoring_status', {
                'status': 'started',
                'message': 'Traffic monitoring started',
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Failed to start traffic monitor: {str(e)}")
            LIVE_MONITORING_ENABLED = False
            socketio.emit('monitoring_status', {
                'status': 'error',
                'message': f'Failed to start monitoring: {str(e)}',
                'timestamp': datetime.now().isoformat()
            })
    else:
        logger.info("Traffic monitor thread already running")
        socketio.emit('monitoring_status', {
            'status': 'already_running',
            'message': 'Traffic monitoring already active',
            'timestamp': datetime.now().isoformat()
        })

def stop_traffic_monitor():
    global LIVE_MONITORING_ENABLED, monitor_thread
    logger.info("Stopping traffic monitor")
    LIVE_MONITORING_ENABLED = False
    
    # Emit status to connected clients
    socketio.emit('monitoring_status', {
        'status': 'stopped',
        'message': 'Traffic monitoring stopped',
        'timestamp': datetime.now().isoformat()
    })
    
    # Wait for thread to finish gracefully
    if monitor_thread and monitor_thread.is_alive():
        try:
            monitor_thread.join(timeout=5)  # Wait up to 5 seconds
            if monitor_thread.is_alive():
                logger.warning("Traffic monitor thread did not stop gracefully")
            else:
                logger.info("Traffic monitor thread stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping traffic monitor: {str(e)}")
    
    monitor_thread = None

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        file = request.files.get('logfile')
        if file:
            try:
                df = pd.read_csv(file)
                print(f"Processing {len(df)} rows from uploaded file")
                if len(df.columns) >= 41:
                    print("Detected NSL-KDD format, using NSL-KDD processor")
                    if nsl_kdd_processor:
                        nsl_kdd_columns = [
                            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
                        ]
                        if len(df.columns) > 41:
                            df = df.iloc[:, :41]
                        df.columns = nsl_kdd_columns
                        features = nsl_kdd_processor.transform(df)
                        predictions = model.predict(features)
                        threat_classes = [get_threat_class(pred) for pred in predictions]
                        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        HISTORICAL_DATA.extend({'time': now, 'prediction': tc} for tc in threat_classes)
                        high_count = threat_classes.count('high')
                        if high_count > 0:
                            alert = {'time': now, 'type': 'Threat', 'level': 'high', 'msg': f'🚨 {high_count} high threats detected!'}
                            ALERTS.append(alert)
                            # Only send one email per analysis
                            send_email_alert('High Threat Alert', f'{high_count} high threats detected!', high_count=high_count, timestamp=now)
                            socketio.emit('live_alert', alert)
                        for i in range(min(5, len(predictions))):
                            print(f"NSL-KDD Raw prediction: {predictions[i]}, Threat class: {threat_classes[i]}")
                    else:
                        flash('NSL-KDD processor not available')
                        return redirect(url_for('index'))
                else:
                    threat_classes = []
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    for _, row in df.iterrows():
                        features = row.values.tolist()
                        pred = classify(features)
                        threat_class = get_threat_class(pred)
                        threat_classes.append(threat_class)
                    HISTORICAL_DATA.extend({'time': now, 'prediction': tc} for tc in threat_classes)
                    high_count = threat_classes.count('high')
                    if high_count > 0:
                        alert = {'time': now, 'type': 'Threat', 'level': 'high', 'msg': f'🚨 {high_count} high threats detected!'}
                        ALERTS.append(alert)
                        send_email_alert('High Threat Alert', f'{high_count} high threats detected!', high_count=high_count, timestamp=now)
                        socketio.emit('live_alert', alert)
                flash(f'Successfully processed {len(df)} records. Found {threat_classes.count("high")} high threats.')
            except Exception as e:
                flash(f'Error processing file: {str(e)}')
                print(f"File processing error: {e}")
            return redirect(url_for('index'))
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

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
                confidence=confidence,
                timestamp=datetime.utcnow()  # Force current timestamp
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
        
        # Update analysis session with totals, distribution, and report
        try:
            analysis_session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
            if analysis_session:
                analysis_session.end_time = datetime.utcnow()
                analysis_session.total_records = len(logs)
                analysis_session.threat_distribution = threat_dist
                analysis_session.report_path = pdf_path
            else:
                logger.error(f"Analysis session {session_id} not found.")
                return jsonify({'error': 'Analysis session not found'}), 404
        except Exception as e:
            logger.error(f"Failed to update analysis session {session_id}: {e}")
            try:
                db_session.rollback()
            except Exception:
                pass
        
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
        print("=== UPLOAD REQUEST RECEIVED ===")
        logger.info("File upload request received")
        
        if 'file' not in request.files:
            print("ERROR: No file in request")
            logger.warning("No file in request")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        print(f"File received: {file.filename}")
        
        if file.filename == '':
            print("ERROR: Empty filename")
            logger.warning("Empty filename")
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            print(f"Saving file to: {filepath}")
            logger.info(f"Saving file to: {filepath}")
            file.save(filepath)
            
            # Create new analysis session
            session_id = str(uuid.uuid4())
            print(f"Created session: {session_id}")
            
            try:
                db_session = db.get_session()
                analysis_session = AnalysisSession(
                    session_id=session_id,
                    analysis_type='file_upload',
                    start_time=datetime.utcnow()
                )
                db_session.add(analysis_session)
                db_session.commit()  # Commit the session to the database
                print("Database session created successfully")
            except Exception as db_error:
                print(f"Database error: {db_error}")
                logger.error(f"Database error: {db_error}")
                return jsonify({'error': f'Database error: {str(db_error)}'}), 500
            
            # Log file upload event
            try:
                upload_event = ThreatEvent(
                    session_id=session_id,
                    event_type='file_upload',
                    event_details={
                        'filename': filename,
                        'filepath': filepath
                    }
                )
                db_session.add(upload_event)
                print("Upload event logged")
            except Exception as event_error:
                print(f"Event logging error: {event_error}")
            
            # Process the file
            print("Starting file processing...")
            results = process_uploaded_file(filepath, session_id, db_session)
            print(f"File processing completed. Results: {results}")
            
            # Clean up
            try:
                os.remove(filepath)
                print("Temporary file cleaned up")
                logger.info("Temporary file cleaned up")
            except Exception as cleanup_error:
                print(f"Cleanup error: {cleanup_error}")
                pass
            
            logger.info("File processing completed successfully")
            print("=== UPLOAD SUCCESS ===")
            return jsonify(results)
        
        print(f"ERROR: Invalid file type: {file.filename}")
        return jsonify({'error': 'Invalid file type. Please use .txt, .csv, or .log files'}), 400
        
    except Exception as e:
        print(f"=== UPLOAD ERROR: {str(e)} ===")
        logger.error(f"Error processing upload: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
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
        print(f"=== PROCESSING FILE: {filepath} ===")
        logger.info(f"Processing uploaded file: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            logs = f.readlines()
        logs = [log.strip() for log in logs if log.strip()]
        print(f"Loaded {len(logs)} log lines")
        logger.info(f"Text file loaded with {len(logs)} lines")
        
        if len(logs) == 0:
            print("ERROR: No valid log lines found")
            return {'error': 'No valid log lines found in file'}
        
        total_logs = len(logs)
        last_emit = time.time()
        def emit_progress(idx):
            percent = int((idx + 1) / total_logs * 100)
            now = time.time()
            # Emit every 5% or at least every 1 second
            if percent % 5 == 0 or percent == 100 or now - emit_progress.last_emit > 1:
                try:
                    # Use request.sid if available for per-user progress, else broadcast
                    from flask import request
                    sid = getattr(request, 'sid', None)
                    if sid:
                        socketio.emit('analyze_progress', {'percent': percent}, to=sid)
                    else:
                        socketio.emit('analyze_progress', {'percent': percent})
                except Exception as e:
                    print(f"[DEBUG] Progress emit error: {e}")
                emit_progress.last_emit = now
        emit_progress.last_emit = time.time()
        
        # Check if it's NSL-KDD format
        is_nsl_kdd = False
        if len(logs) > 0:
            first_line = logs[0].split(',')
            print(f"First line has {len(first_line)} columns")
            if len(first_line) >= 41:
                is_nsl_kdd = True
                print("Detected NSL-KDD format")
        
        if is_nsl_kdd and nsl_kdd_processor:
            print("Processing as NSL-KDD data...")
            # Process as NSL-KDD data
            split_lines = [log.split(',') for log in logs]
            if len(split_lines[0]) == 43:
                split_lines = [cols[:-1] for cols in split_lines]
            df = pd.DataFrame(split_lines, columns=nsl_kdd_processor.feature_names + ['label'])
            print(f"Created DataFrame with shape: {df.shape}")
            
            features = nsl_kdd_processor.transform(df)
            print(f"Transformed features shape: {features.shape}")
            
            if os.path.exists('models/nsl_kdd_model.pkl'):
                print("Loading NSL-KDD model...")
                nsl_kdd_model = joblib.load('models/nsl_kdd_model.pkl')
                predictions = nsl_kdd_model.predict(features)
                probabilities = nsl_kdd_model.predict_proba(features)
                print(f"NSL-KDD predictions made: {len(predictions)}")
            else:
                print("NSL-KDD model not found, falling back to regular classifier")
                logger.warning("NSL-KDD model not found, falling back to regular classifier")
                predictions = classifier.predict(features)
                probabilities = classifier.predict_proba(features)
        else:
            print("Processing as regular log data...")
            processed_logs = data_processor.process_logs(logs)
            print(f"Processed logs shape: {processed_logs.shape}")
            
            predictions = classifier.predict(processed_logs)
            probabilities = classifier.predict_proba(processed_logs)
            print(f"Regular predictions made: {len(predictions)}")
        
        threat_levels = ['Low', 'Medium', 'High']
        log_entries = []
        
        print("Creating log entries...")
        for idx, (log, pred, prob) in enumerate(zip(logs, predictions, probabilities)):
            threat_level = threat_levels[int(pred)]
            confidence = float(prob.max())
            log_entry = LogEntry(
                session_id=session_id,
                log_text=str(log)[:1000],
                threat_level=threat_level,
                confidence=confidence,
                timestamp=datetime.utcnow()
            )
            log_entries.append(log_entry)
            emit_progress(idx)
        
        print(f"Created {len(log_entries)} log entries")

        # Bulk insert all log entries at once
        if log_entries:
            print("Saving to database...")
            db_session.bulk_save_objects(log_entries)
            db_session.commit()
            print("Database save completed")

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
        
        print(f"Threat distribution: {threat_dist}")
        
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

        # Color the slices
        pie.slices[0].fillColor = colors.green  # Low threat - green
        pie.slices[1].fillColor = colors.yellow  # Medium threat - yellow
        pie.slices[2].fillColor = colors.red  # High threat - red

        drawing.add(pie)
        story.append(drawing)
        story.append(Spacer(1, 12))

        # Summary table
        summary_data = [['Threat Level', 'Count', 'Percentage']]
        for level in threat_levels:
            summary_data.append([level, str(threat_dist[level]), f"{percentages[level]:.1f}%"])

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

        # Build PDF
        doc.build(story)
        print(f"PDF report generated: {pdf_path}")

        # Update analysis session with totals, distribution, and report
        try:
            analysis_session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
            if analysis_session:
                analysis_session.end_time = datetime.utcnow()
                analysis_session.total_records = total_logs
                analysis_session.threat_distribution = threat_dist
                analysis_session.report_path = pdf_path

                # Log completion event with summary details
                completion_event = ThreatEvent(
                    session_id=session_id,
                    event_type='analysis_complete',
                    event_details={
                        'total_records': total_logs,
                        'threat_distribution': threat_dist,
                        'report_path': pdf_path
                    }
                )
                db_session.add(completion_event)

                db_session.commit()
            else:
                print(f"[WARN] Analysis session {session_id} not found for update")
        except Exception as e:
            print(f"[ERROR] Failed to update analysis session: {e}")
            try:
                db_session.rollback()
            except Exception:
                pass

        # Emit completion event
        try:
            socketio.emit('analysis_complete', {'session_id': session_id})
            print("Analysis complete event emitted")
        except Exception as emit_error:
            print(f"Emit error: {emit_error}")

        # Send email alert summary if uploaded file contains high threats
        try:
            high_count = threat_dist.get('High', 0)
            if high_count > 0:
                send_email_alert(
                    subject="",
                    body="",
                    high_count=high_count,
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                )
        except Exception as e:
            logger.warning(f"Upload email alert failed: {e}")

        print("=== PROCESSING COMPLETE ===")
        return {
            'success': True,
            'session_id': session_id,
            'total_logs': total_logs,
            'threat_distribution': threat_dist,
            'pdf_path': pdf_path
        }
        
    except Exception as e:
        print(f"=== PROCESSING ERROR: {str(e)} ===")
        logger.error(f"Error processing uploaded file: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {'error': f'Processing error: {str(e)}'}

@app.route('/api/audit/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Return a list of all analysis sessions (most recent first)"""
    db_session = db.get_session()
    try:
        sessions = db_session.query(AnalysisSession).order_by(AnalysisSession.start_time.desc()).all()
        result = []
        for s in sessions:
            # Parse the threat_distribution JSON if it's stored as a string
            threat_dist = s.threat_distribution
            if isinstance(threat_dist, str):
                try:
                    import json
                    threat_dist = json.loads(threat_dist)
                except:
                    threat_dist = {"Low": 0, "Medium": 0, "High": 0}
            
            result.append({
                'session_id': s.session_id,
                'start_time': s.start_time.isoformat() if s.start_time else None,
                'end_time': s.end_time.isoformat() if s.end_time else None,
                'total_records': s.total_records,
                'threat_distribution': threat_dist,
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
@login_required
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
        
        # Normalize threat_distribution to dict if stored as JSON string
        threat_dist = session.threat_distribution
        if isinstance(threat_dist, str):
            try:
                import json
                threat_dist = json.loads(threat_dist)
            except Exception:
                threat_dist = {"Low": 0, "Medium": 0, "High": 0}
        
        result = {
            'session_id': session.session_id,
            'start_time': session.start_time.isoformat() if session.start_time else None,
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'total_records': session.total_records,
            'threat_distribution': threat_dist,
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
@login_required
def audit_page():
    # Allow all authenticated users to access audit page
    return render_template('audit.html')

@app.route('/download_report')
@login_required
def download_report():
    session_id = request.args.get('session_id')
    
    if session_id:
        # Get session data from database
        db_session = db.get_session()
        try:
            analysis_session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
            if not analysis_session:
                flash('Session not found', 'danger')
                return redirect(url_for('audit_page'))
            
            # Resolve existing or create new report path
            path = analysis_session.report_path
            if not path or not os.path.exists(path):
                # Generate a per-session report if missing
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join('static', 'reports', f'report_{session_id}_{timestamp}.pdf')
                os.makedirs(os.path.dirname(path), exist_ok=True)
                generate_pdf_report(HISTORICAL_DATA, path)
                analysis_session.report_path = path
                db_session.commit()
            
            # Serve from the reports directory to avoid path issues
            directory = os.path.dirname(path)
            filename = os.path.basename(path)
            return send_from_directory(directory, filename, as_attachment=True, download_name=filename, mimetype='application/pdf')
        except Exception as e:
            flash(f'Error generating report: {str(e)}', 'danger')
            return redirect(url_for('audit_page'))
        finally:
            db_session.close()
    else:
        # Generate general report if no session specified
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join('static', 'reports', f'report_{timestamp}.pdf')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        generate_pdf_report(HISTORICAL_DATA, path)
        directory = os.path.dirname(path)
        filename = os.path.basename(path)
        return send_from_directory(directory, filename, as_attachment=True, download_name=filename, mimetype='application/pdf')


@app.route('/api/pie')
def api_pie():
    """Pie chart data for a specific session or latest session"""
    db_session = db.get_session()
    try:
        # Get session_id from query parameter or use latest session
        session_id = request.args.get('session_id')
        if session_id:
            session = db_session.query(AnalysisSession).filter_by(session_id=session_id).first()
        else:
            session = db_session.query(AnalysisSession).order_by(AnalysisSession.start_time.desc()).first()
        
        if not session:
            return jsonify({'low': 0, 'medium': 0, 'high': 0})
        
        # Query log entries for this session
        log_entries = db_session.query(LogEntry).filter(LogEntry.session_id == session.session_id).all()
        counts = {'low': 0, 'medium': 0, 'high': 0}
        for entry in log_entries:
            threat_level = entry.threat_level.lower()
            if threat_level in ['low', 'normal']:
                counts['low'] += 1
            elif threat_level in ['medium', 'moderate']:
                counts['medium'] += 1
            elif threat_level in ['high', 'critical']:
                counts['high'] += 1
        print(f"[DEBUG] /api/pie (session {session.session_id}): {counts}")
        return jsonify(counts)
    except Exception as e:
        logger.error(f"Error fetching pie chart data: {str(e)}")
        return jsonify({'low': 0, 'medium': 0, 'high': 0})
    finally:
        db_session.close()

@app.route('/api/trends')
def api_trends():
    """Trend data for a specific session or last 30 days (all logs)"""
    db_session = db.get_session()
    try:
        session_id = request.args.get('session_id')
        if session_id:
            # Get trends for specific session
            log_entries = db_session.query(LogEntry).filter(
                LogEntry.session_id == session_id
            ).order_by(LogEntry.timestamp).all()
        else:
            # Get trends for last 30 days (all logs)
            cutoff = datetime.now() - timedelta(days=30)
            log_entries = db_session.query(LogEntry).filter(
                LogEntry.timestamp >= cutoff
            ).order_by(LogEntry.timestamp).all()
        
        trends = {}
        for entry in log_entries:
            day = entry.timestamp.strftime('%Y-%m-%d')
            if day not in trends:
                trends[day] = {'low': 0, 'medium': 0, 'high': 0}
            threat_level = entry.threat_level.lower()
            if threat_level in ['low', 'normal']:
                trends[day]['low'] += 1
            elif threat_level in ['medium', 'moderate']:
                trends[day]['medium'] += 1
            elif threat_level in ['high', 'critical']:
                trends[day]['high'] += 1
        trend_list = [{'date': k, **v} for k, v in sorted(trends.items())]
        scope = f"session {session_id}" if session_id else "all logs"
        print(f"[DEBUG] /api/trends ({scope}): {trend_list}")
        return jsonify(trend_list)
    except Exception as e:
        logger.error(f"Error fetching trends: {str(e)}")
        return jsonify([])
    finally:
        db_session.close()

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    print(f'Client namespace: {request.namespace}')
    emit('connection_status', {'status': 'connected'})
    # Emit current monitoring status to newly connected client
    emit('monitoring_status', {'enabled': LIVE_MONITORING_ENABLED})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('ping')
def handle_ping():
    print('Ping received from client')
    emit('pong')

# Add heartbeat mechanism
@socketio.on('heartbeat')
def handle_heartbeat():
    emit('heartbeat_response', {'timestamp': datetime.now().isoformat()})

# Database activity monitoring
@socketio.on('join_db_monitoring')
def handle_join_db_monitoring():
    print(f'Client joined database monitoring: {request.sid}')
    emit('db_monitoring_status', {'status': 'connected'})

@socketio.on('leave_db_monitoring')
def handle_leave_db_monitoring():
    print(f'Client left database monitoring: {request.sid}')

# Function to emit database activity updates
def emit_db_activity():
    try:
        # Simulate database activity metrics (in a real app, you'd track actual DB operations)
        import random
        activity_data = {
            'queries_per_minute': random.randint(10, 50),
            'inserts_per_minute': random.randint(2, 15),
            'errors_per_minute': random.randint(0, 3),
            'timestamp': datetime.now().isoformat()
        }
        socketio.emit('db_activity_update', activity_data)
    except Exception as e:
        print(f"Error emitting database activity: {e}")

# Background task for database activity monitoring
def db_activity_monitor():
    while True:
        try:
            emit_db_activity()
            time.sleep(5)  # Update every 5 seconds
        except Exception as e:
            print(f"Database activity monitor error: {e}")
            time.sleep(10)

# Start database activity monitoring thread
db_monitor_thread = threading.Thread(target=db_activity_monitor, daemon=True)
db_monitor_thread.start()

@app.route('/monitor', methods=['GET', 'POST'])
@login_required
def monitor():
    global LIVE_MONITORING_ENABLED
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'start':
                LIVE_MONITORING_ENABLED = True
                start_traffic_monitor()
                socketio.emit('monitoring_status', {'enabled': True, 'reason': 'manual_start'})
                return jsonify({
                    'success': True,
                    'message': 'Live monitoring started successfully',
                    'status': 'running'
                })
            elif action == 'stop':
                LIVE_MONITORING_ENABLED = False
                stop_traffic_monitor()
                socketio.emit('monitoring_status', {'enabled': False, 'reason': 'manual_stop'})
                return jsonify({
                    'success': True,
                    'message': 'Live monitoring stopped successfully',
                    'status': 'stopped'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid action specified'
                }), 400
        except Exception as e:
            logger.error(f"Error in monitor action '{action}': {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error {action}ing monitoring: {str(e)}'
            }), 500
    return render_template('monitor.html', monitoring=LIVE_MONITORING_ENABLED)

@app.route('/api/test-alert', methods=['POST'])
@login_required
def test_alert():
    """Generate a test alert for debugging"""
    try:
        data = request.get_json() or {}
        message = data.get('message', 'Test alert from API')
        
        alert = {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'Test',
            'level': 'warning',
            'msg': f'🧪 {message}'
        }
        
        ALERTS.append(alert)
        socketio.emit('live_alert', alert)
        
        return jsonify({'success': True, 'alert': alert})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-email-alert', methods=['POST'])
@login_required
def test_email_alert():
    """Send a test email alert.
    Accepts JSON with optional fields:
    - subject: email subject
    - body: email body
    - severity: 'medium' or 'high' (uses cooldown and live-alert template)
    - messages: list of strings (used when severity provided)
    - high_count: integer (used for classification-style subject/body)
    - timestamp: ISO or '%Y-%m-%d %H:%M:%S' string
    """
    try:
        data = request.get_json() or {}
        subject = data.get('subject') or '[Network Threat Classifier] Test Email Alert'
        body = data.get('body') or 'This is a test email alert.'
        severity = data.get('severity')
        messages = data.get('messages') or []
        high_count = data.get('high_count')
        timestamp = data.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        used_cooldown_path = False
        if severity in ['medium', 'high'] and len(messages) > 0:
            used_cooldown_path = True
            sent = maybe_send_email_live_alert(severity, messages)
        else:
            ts_arg = timestamp if high_count is not None else None
            sent = send_email_alert(subject, body, high_count=high_count, timestamp=ts_arg)

        return jsonify({'success': bool(sent), 'used_cooldown_path': used_cooldown_path})
    except Exception as e:
        logger.error(f"test_email_alert error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@login_required
def api_alerts():
    """Return recent alerts for the dashboard.
    Frontend expects a list of alert dicts: {time, type, level, msg}.
    We return the last 200 alerts, newest last (frontend reverses as needed).
    """
    try:
        # Ensure we return a JSON-serializable list
        alerts = ALERTS[-200:]
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify([])

@app.route('/db_health')
@login_required
def db_health_page():
    # Only admins can access db health page
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    return render_template('db_health.html')

@app.route('/api/db_health')
@login_required
def api_db_health():
    # Only admins can access db health API
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    db_session = db.get_session()
    try:
        db_size = 'N/A'
        db_limit = '10 GB (Neon Free Tier)'
        percent_used = 'N/A'
        log_count = 0
        session_count = 0
        
        # Performance metrics
        query_response_time = 0
        connection_pool_active = 0
        connection_pool_size = 10
        
        # Table breakdown data
        table_breakdown = []
        
        try:
            engine = db_session.get_bind()
            
            # Measure query response time
            start_time = time.time()
            db_session.execute(text('SELECT 1')).scalar()
            query_response_time = round((time.time() - start_time) * 1000, 2)  # in milliseconds
            
            # Get connection pool info
            try:
                pool = engine.pool
                connection_pool_active = pool.checkedout()
                connection_pool_size = pool.size()
            except:
                connection_pool_active = 1  # Current connection
                connection_pool_size = 10  # Default
            
            try:
                # SQLite database size query
                import os
                db_path = getattr(engine.url, 'database', None)
                if db_path and os.path.exists(db_path):
                    size_bytes = os.path.getsize(db_path)
                    db_size = f"{round(size_bytes / (1024*1024), 2)} MB"
                    percent_used = round(size_bytes / (10*1024*1024*1024) * 100, 2)
                else:
                    db_size = "Unknown"
                    percent_used = 0
            except Exception as e:
                db_size = "Unknown"
                percent_used = 'N/A'
                print(f"[DB Health] Could not determine DB size: {e}")
            
            # Get table-wise breakdown
            try:
                tables = ['log_entries', 'analysis_sessions', 'threat_events', 'users']
                for table in tables:
                    try:
                        count = db_session.execute(text(f'SELECT COUNT(*) FROM {table}')).scalar()
                        # Estimate size (rough calculation)
                        estimated_size = count * 0.5  # KB per record estimate
                        table_breakdown.append({
                            'name': table.replace('_', ' ').title(),
                            'records': count,
                            'size_kb': round(estimated_size, 2)
                        })
                    except Exception as e:
                        print(f"[DB Health] Could not get info for table {table}: {e}")
                        table_breakdown.append({
                            'name': table.replace('_', ' ').title(),
                            'records': 0,
                            'size_kb': 0
                        })
            except Exception as e:
                print(f"[DB Health] Could not get table breakdown: {e}")
            
            try:
                log_count = db_session.execute(text('SELECT COUNT(*) FROM log_entries')).scalar()
            except Exception as e:
                print(f"[DB Health] Could not count log_entries: {e}")
                log_count = 'N/A'
            try:
                session_count = db_session.execute(text('SELECT COUNT(*) FROM analysis_sessions')).scalar()
            except Exception as e:
                print(f"[DB Health] Could not count analysis_sessions: {e}")
                session_count = 'N/A'
        except Exception as e:
            print(f"[DB Health] General error: {e}")
        
        return jsonify({
            'db_size': db_size,
            'db_limit': db_limit,
            'percent_used': percent_used,
            'log_count': log_count,
            'session_count': session_count,
            'performance': {
                'query_response_time': query_response_time,
                'connection_pool_active': connection_pool_active,
                'connection_pool_size': connection_pool_size,
                'connection_pool_usage': round((connection_pool_active / connection_pool_size) * 100, 1)
            },
            'table_breakdown': table_breakdown
        })
    finally:
        db_session.close()

@app.route('/api/db_cleanup', methods=['POST'])
@login_required
def api_db_cleanup():
    # Only admins can perform db cleanup
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    from flask import request
    db_session = db.get_session()
    try:
        days = int(request.json.get('days', 30))
        cutoff = datetime.now() - timedelta(days=days)
        
        # Count records before deletion for reporting
        old_logs_count = db_session.query(LogEntry).filter(LogEntry.timestamp < cutoff).count()
        old_events_count = db_session.query(ThreatEvent).filter(ThreatEvent.timestamp < cutoff).count()
        old_sessions_count = db_session.query(AnalysisSession).filter(AnalysisSession.start_time < cutoff).count()
        
        # Delete old records using ORM
        db_session.query(LogEntry).filter(LogEntry.timestamp < cutoff).delete()
        db_session.query(ThreatEvent).filter(ThreatEvent.timestamp < cutoff).delete()
        db_session.query(AnalysisSession).filter(AnalysisSession.start_time < cutoff).delete()
        
        db_session.commit()
        
        total_deleted = old_logs_count + old_events_count + old_sessions_count
        return jsonify({
            'message': f"Successfully deleted {total_deleted} records older than {days} days. (Logs: {old_logs_count}, Events: {old_events_count}, Sessions: {old_sessions_count})"
        })
    except Exception as e:
        db_session.rollback()
        logger.error(f"Database cleanup error: {str(e)}")
        return jsonify({'error': f"Cleanup failed: {str(e)}"}), 500
    finally:
        db_session.close()

# ============================================================================
# TEST ROUTES (NO AUTHENTICATION REQUIRED)
# ============================================================================

@app.route('/test-monitor')
def test_monitor():
    """Test monitoring page that bypasses authentication"""
    return render_template('test_monitor.html')

@app.route('/test-monitor/start', methods=['POST'])
def test_monitor_start():
    """Start monitoring without authentication for testing"""
    global LIVE_MONITORING_ENABLED
    try:
        LIVE_MONITORING_ENABLED = True
        start_traffic_monitor()
        socketio.emit('monitoring_status', {
            'enabled': True, 
            'reason': 'test_start',
            'timestamp': datetime.now().isoformat()
        })
        logger.info("Test monitoring started")
        return jsonify({
            'success': True, 
            'message': 'Test monitoring started successfully',
            'status': 'running'
        })
    except Exception as e:
        logger.error(f"Error starting test monitoring: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error starting monitoring: {str(e)}'
        }), 500

@app.route('/test-monitor/stop', methods=['POST'])
def test_monitor_stop():
    """Stop monitoring without authentication for testing"""
    global LIVE_MONITORING_ENABLED
    try:
        LIVE_MONITORING_ENABLED = False
        stop_traffic_monitor()
        socketio.emit('monitoring_status', {
            'enabled': False, 
            'reason': 'test_stop',
            'timestamp': datetime.now().isoformat()
        })
        logger.info("Test monitoring stopped")
        return jsonify({
            'success': True, 
            'message': 'Test monitoring stopped successfully',
            'status': 'stopped'
        })
    except Exception as e:
        logger.error(f"Error stopping test monitoring: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error stopping monitoring: {str(e)}'
        }), 500

@app.route('/test-monitor/status')
def test_monitor_status():
    """Get monitoring status without authentication for testing"""
    return jsonify({
        'monitoring_enabled': LIVE_MONITORING_ENABLED,
        'alerts_count': len(ALERTS),
        'traffic_history_count': len(TRAFFIC_HISTORY),
        'monitor_thread_active': monitor_thread is not None and monitor_thread.is_alive() if monitor_thread else False,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/test-monitor/generate-alert', methods=['POST'])
def test_generate_alert():
    """Generate a test alert for WebSocket testing"""
    try:
        data = request.get_json() or {}
        alert_type = data.get('type', 'DDoS')
        severity = data.get('severity', 'high')
        message = data.get('message', 'Test threat detected')
        
        alert = {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'level': severity,
            'msg': f'🧪 TEST: {message}',
            'source_ip': data.get('source_ip', '192.168.1.100'),
            'dest_ip': data.get('dest_ip', '10.0.0.1'),
            'protocol': data.get('protocol', 'TCP'),
            'test_alert': True
        }
        
        ALERTS.append(alert)
        socketio.emit('live_alert', alert)
        logger.info(f"Test alert generated: {alert}")
        
        return jsonify({
            'success': True, 
            'alert': alert,
            'message': 'Test alert generated and emitted'
        })
    except Exception as e:
        logger.error(f"Error generating test alert: {str(e)}")
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print("🚀 Starting Network Threat Classifier...")
    
    # Try different ports if the default one is in use
    port = 5000
    max_port = 5010  # Try up to this port
    
    while port <= max_port:
        try:
            print(f"📊 Attempting to start on port {port}...")
            print("🔍 Live monitoring and alerts enabled")
            print("📧 Email alerts configured")
            print("=" * 50)
            
            # Train model if not already trained
            if not classifier.is_trained():
                logger.info("Training initial model...")
                classifier.train()
                logger.info("Model training completed")
            
            # Start the server with a specific port
            print(f"📊 Dashboard available at: http://localhost:{port}")
            socketio.run(app, debug=True, host='0.0.0.0', port=port)
            break
        except OSError as e:
            print(f"Port {port} is in use, trying next port...")
            port += 1
            
    if port > max_port:
        print("❌ Failed to find an available port. Please close other applications and try again.")
