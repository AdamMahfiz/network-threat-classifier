"""
Train model on NSL-KDD dataset
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import logging

sys.path.append('src')
from src.threat_classifier.data.nsl_kdd_processor import NSLKDDProcessor
from src.threat_classifier.utils.logger import setup_logger

# Setup logging
logger = setup_logger('nsl_kdd_trainer', 'logs/nsl_kdd_training.log')

def train_nsl_kdd_model(train_file: str, test_file: str = None):
    """Train model on NSL-KDD dataset"""
    logger.info("Starting NSL-KDD model training...")
    
    # Initialize processor
    processor = NSLKDDProcessor()
    
    # Load and process training data
    logger.info(f"Loading training data from {train_file}")
    train_df = pd.read_csv(train_file, names=processor.feature_names + ['label'], index_col=False)
    
    # Print threat level distribution
    threat_levels = train_df['label'].apply(processor.get_threat_level)
    threat_distribution = pd.Series(threat_levels).value_counts()
    logger.info("\nThreat Level Distribution in Training Data:")
    logger.info(f"Low (0): {threat_distribution.get(0, 0)}")
    logger.info(f"Medium (1): {threat_distribution.get(1, 0)}")
    logger.info(f"High (2): {threat_distribution.get(2, 0)}")
    
    # Fit processor on training data
    processor.fit(train_df)
    
    # Process training data
    X_train, y_train = processor.process_csv(train_file)
    
    # Initialize and train model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    logger.info("Training model...")
    model.fit(X_train, y_train)
    
    # Evaluate on training data
    y_pred = model.predict(X_train)
    train_accuracy = accuracy_score(y_train, y_pred)
    logger.info(f"Training accuracy: {train_accuracy:.4f}")
    logger.info("\nTraining Classification Report:")
    logger.info(classification_report(y_train, y_pred, target_names=['Low', 'Medium', 'High']))
    
    # Evaluate on test data if provided
    if test_file:
        logger.info(f"Evaluating on test data from {test_file}")
        X_test, y_test = processor.process_csv(test_file)
        y_pred = model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Test accuracy: {test_accuracy:.4f}")
        logger.info("\nTest Classification Report:")
        logger.info(classification_report(y_test, y_pred, target_names=['Low', 'Medium', 'High']))
    
    # Save model and processor
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/nsl_kdd_model.pkl')
    joblib.dump(processor, 'models/nsl_kdd_processor.pkl')
    logger.info("Model and processor saved successfully")
    
    return model, processor

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python train_nsl_kdd_model.py <train_file> [test_file]")
        sys.exit(1)
    
    train_file = sys.argv[1]
    test_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    train_nsl_kdd_model(train_file, test_file) 