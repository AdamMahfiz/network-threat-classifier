# Network Threat Classification System - Setup Guide

## Features
- ✅ File and text log analysis with NSL-KDD model
- ✅ Real-time email alerts for high threats
- ✅ Live browser pop-up alerts via SocketIO
- ✅ Live network traffic monitoring
- ✅ DDoS detection and alerts
- ✅ Environment-based configuration

## Quick Setup

### 1. Environment Configuration
Copy the template and configure your email settings:
```bash
cp env_template.txt .env
```

Edit `.env` with your email settings:
```env
# Email Configuration (Gmail example)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com
MAIL_RECIPIENT=recipient@example.com

# Network Monitoring Configuration
TRAFFIC_THRESHOLD=1000
DDOS_THRESHOLD=5000
```

**Note:** For Gmail, use an "App Password" instead of your regular password.

### 2. Install Dependencies
```bash
# Activate virtual environment
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 3. Train the Model
```bash
python train_nsl_kdd_model.py
```

### 4. Run the Application
```bash
python app.py
```

Visit: http://127.0.0.1:5000/

## Usage

### Main Dashboard
- Upload NSL-KDD log files (.txt, .csv)
- Paste log data for analysis
- View real-time results with threat classification

### Live Traffic Monitor
- Click "Live Traffic" in navigation
- Click "Start Monitoring" to begin
- View real-time traffic feed and charts
- Receive alerts for threats and DDoS attacks

### Alert System
- **Email Alerts**: Sent automatically when high threats detected
- **Browser Alerts**: Real-time pop-up notifications
- **DDoS Alerts**: Triggered when traffic exceeds threshold

## File Structure
```
network-threat-classifier/
├── app.py                 # Main Flask application
├── train_nsl_kdd_model.py # Model training script
├── requirements.txt       # Python dependencies
├── .env                   # Environment configuration
├── env_template.txt       # Environment template
├── models/                # Trained models
├── templates/             # HTML templates
│   ├── index.html        # Main dashboard
│   └── live_traffic.html # Live monitoring page
└── data/                  # NSL-KDD dataset
```

## Configuration Options

### Email Settings
- `MAIL_SERVER`: SMTP server (e.g., smtp.gmail.com)
- `MAIL_PORT`: SMTP port (usually 587 for TLS)
- `MAIL_USERNAME`: Your email address
- `MAIL_PASSWORD`: App password (not regular password)
- `MAIL_RECIPIENT`: Where to send alerts

### Monitoring Thresholds
- `TRAFFIC_THRESHOLD`: Normal traffic threshold
- `DDOS_THRESHOLD`: DDoS detection threshold (packets/sec)

## Troubleshooting

### Email Not Sending
1. Check your `.env` configuration
2. For Gmail: Enable 2FA and generate an App Password
3. Check firewall/antivirus blocking SMTP

### Model Not Loading
1. Run `python train_nsl_kdd_model.py` first
2. Ensure NSL-KDD data is in `data/nsl-kdd/` directory

### Live Monitoring Issues
1. Check browser console for SocketIO errors
2. Ensure no firewall blocking WebSocket connections
3. Try refreshing the page

## Security Notes
- Keep your `.env` file secure and never commit it to version control
- Use strong, unique passwords for email accounts
- Consider using environment variables in production
- The live monitoring currently uses simulated data - replace with real packet capture for production use 