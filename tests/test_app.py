"""
Basic tests for the application
"""

def test_app_import():
    """Test that the app can be imported"""
    from app import app
    assert app is not None

def test_health_endpoint():
    """Test the health endpoint"""
    from app import app
    
    with app.test_client() as client:
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

def test_threat_classifier():
    """Test threat classifier functionality"""
    from src.threat_classifier.models.threat_classifier import ThreatClassifier
    
    classifier = ThreatClassifier()
    # Test with synthetic data
    X, y = classifier._generate_training_data(100)
    assert X.shape[0] == 100
    assert len(y) == 100

def test_data_processor():
    """Test data processor functionality"""
    from src.threat_classifier.data.data_processor import DataProcessor
    
    processor = DataProcessor()
    logs = [
        "Failed login attempt from 192.168.1.100",
        "Port scan detected from 10.0.0.5"
    ]
    
    features = processor.process_logs(logs)
    assert features.shape[0] == 2
    assert features.shape[1] == 20
