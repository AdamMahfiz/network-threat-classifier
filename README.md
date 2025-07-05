# Network Threat Classification System

AI-powered network security analysis system for classifying network traffic and log entries into threat levels.

## Features

- **Web Interface**: Upload files or paste logs directly
- **AI Classification**: Automatic threat level detection (Low/Medium/High)
- **Visual Analytics**: Charts and detailed results
- **File Support**: CSV, TXT, and LOG files
- **Real-time Analysis**: Instant results
- **REST API**: Programmatic access to classification
- **CLI Tool**: Command-line interface for batch processing

## Quick Start

### 1. Setup Environment
\`\`\`bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
\`\`\`

### 2. Configure Environment
\`\`\`bash
cp .env.example .env
# Edit .env with your database credentials
\`\`\`

### 3. Run Application
\`\`\`bash
python app.py
\`\`\`

### 4. Open Browser
Navigate to `http://localhost:5000`

## Usage

### Web Interface
1. Click "Generate Sample" to load sample network logs
2. Click "Analyze Text" to classify the logs
3. View results with charts and detailed classifications
4. Upload your own log files for analysis

### CLI Tool
\`\`\`bash
# Train the model
python cli.py train

# Classify logs from file
python cli.py predict logs.txt

# Show model info
python cli.py info
\`\`\`

### API Endpoints
- `GET /` - Main web interface
- `GET /health` - Health check
- `POST /api/classify` - Classify log text
- `POST /api/upload` - Upload and classify file

## Testing
\`\`\`bash
pytest tests/ -v
\`\`\`

## Development
\`\`\`bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Run with development server
python app.py
\`\`\`

## Project Structure
\`\`\`
network-threat-classifier/
├── app.py                          # Main Flask application
├── cli.py                          # Command-line interface
├── src/threat_classifier/
│   ├── models/threat_classifier.py # ML model
│   ├── data/data_processor.py      # Data processing
│   └── utils/logger.py             # Logging utilities
├── templates/index.html            # Web interface
├── tests/                          # Unit tests
├── models/                         # Trained model storage
├── logs/                           # Application logs
└── uploads/                        # Temporary file storage
\`\`\`

## Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License
MIT License - see LICENSE file for details.
