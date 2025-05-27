"""
Command Line Interface for Network Threat Classifier
"""

import argparse
import sys
import os
import json
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.threat_classifier.models.threat_classifier import ThreatClassifier
from src.threat_classifier.data.data_processor import DataProcessor
from src.threat_classifier.utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description='Network Threat Classification CLI')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the classification model')
    train_parser.add_argument('--output', '-o', default='model_results.json',
                             help='Output file for training results')
    
    # Predict command
    predict_parser = subparsers.add_parser('predict', help='Classify network logs')
    predict_parser.add_argument('input', help='Input file (CSV or text logs)')
    predict_parser.add_argument('--output', '-o', default='predictions.json',
                               help='Output file for predictions')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show model information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    logger = setup_logger('cli', 'logs/cli.log')
    
    # Initialize components
    classifier = ThreatClassifier()
    data_processor = DataProcessor()
    
    try:
        if args.command == 'train':
            handle_train(classifier, args, logger)
        elif args.command == 'predict':
            handle_predict(classifier, data_processor, args, logger)
        elif args.command == 'info':
            handle_info(classifier, logger)
            
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        sys.exit(1)

def handle_train(classifier, args, logger):
    """Handle model training"""
    logger.info("Starting model training...")
    
    accuracy = classifier.train()
    
    results = {
        'accuracy': accuracy,
        'timestamp': datetime.now().isoformat(),
        'status': 'completed'
    }
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Training completed. Results saved to {args.output}")
    print(f"Model trained with accuracy: {accuracy:.4f}")

def handle_predict(classifier, data_processor, args, logger):
    """Handle prediction on new data"""
    logger.info(f"Processing file: {args.input}")
    
    if not os.path.exists(args.input):
        raise FileNotFoundError(f"Input file not found: {args.input}")
    
    # Process input
    with open(args.input, 'r') as f:
        logs = f.readlines()
    
    processed_logs = data_processor.process_logs(logs)
    predictions = classifier.predict(processed_logs)
    probabilities = classifier.predict_proba(processed_logs)
    
    threat_levels = ['Low', 'Medium', 'High']
    results = {
        'total_logs': len(logs),
        'predictions': [
            {
                'log': log.strip(),
                'threat_level': threat_levels[pred],
                'confidence': float(prob.max())
            }
            for log, pred, prob in zip(logs, predictions, probabilities)
        ],
        'threat_distribution': {
            'Low': int((predictions == 0).sum()),
            'Medium': int((predictions == 1).sum()),
            'High': int((predictions == 2).sum())
        },
        'timestamp': datetime.now().isoformat()
    }
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Predictions saved to {args.output}")
    print(f"Processed {len(logs)} logs. Results saved to {args.output}")

def handle_info(classifier, logger):
    """Handle model info display"""
    logger.info("Retrieving model information...")
    
    if not classifier.is_trained():
        print("No trained model found. Please train the model first using 'python cli.py train'")
        return
    
    print("Model Information:")
    print("=" * 50)
    print("Status: Trained")
    print("Type: Random Forest Classifier")
    print("Features: 20")
    print("Classes: 3 (Low, Medium, High)")

if __name__ == '__main__':
    main()
