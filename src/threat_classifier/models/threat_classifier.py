"""
Enhanced Threat Classification Model with Adjusted Sensitivity
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import joblib
import os
import logging

logger = logging.getLogger('threat_classifier')

class ThreatClassifier:
    """Enhanced threat classification with adjusted sensitivity"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=12, 
            min_samples_split=3,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        self.model_dir = 'models'
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Automatically load model if it exists
        if self.is_trained():
            self._load_model()
        
    def train(self):
        """Train the model with adjusted thresholds"""
        logger.info("Starting model training with adjusted sensitivity...")
        
        # Generate training data with better separation
        X, y = self._generate_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model trained with accuracy: {accuracy:.4f}")
        
        # Save model
        self._save_model()
        
        return accuracy
    
    def predict(self, X):
        """Make predictions with enhanced rule-based logic"""
        self._ensure_model_ready()
        X_scaled = self.scaler.transform(X)
    
        # Get base predictions
        base_predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # Apply enhanced logic based on feature scores
        enhanced_predictions = []
        
        for i, (pred, prob) in enumerate(zip(base_predictions, probabilities)):
            feature_sum = np.sum(X[i])
            max_feature = np.max(X[i])
            
            # More balanced rule-based overrides
            if feature_sum > 90 and max_feature > 20:  # Only very clear high threats
                enhanced_predictions.append(2)  # HIGH
            elif feature_sum > 60 and max_feature > 12:  # Clear medium threats
                enhanced_predictions.append(1)  # MEDIUM
            elif feature_sum < 20 and max_feature < 5:  # Clear low threats
                enhanced_predictions.append(0)  # LOW
            else:
                enhanced_predictions.append(pred)  # Keep original prediction
        
        return np.array(enhanced_predictions)
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        self._ensure_model_ready()
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def predict_with_rules(self, X):
        """Enhanced prediction with rule-based overrides"""
        # Get base ML predictions
        base_predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        
        # Apply rule-based overrides for obvious cases
        enhanced_predictions = []
        
        for i, (pred, prob) in enumerate(zip(base_predictions, probabilities)):
            # Get the original log text if available
            # For now, we'll use the feature vector to make decisions
            feature_sum = np.sum(X[i])
            
            # Rule-based overrides based on feature analysis
            if feature_sum > 80:  # Very high feature score
                enhanced_predictions.append(2)  # Force HIGH
            elif feature_sum > 50:  # Medium-high feature score
                enhanced_predictions.append(1)  # Force MEDIUM
            else:
                enhanced_predictions.append(pred)  # Keep original
        
        return np.array(enhanced_predictions)
    
    def _ensure_model_ready(self):
        """Ensure model is trained and loaded"""
        if not self.is_trained():
            print("Model not trained. Training now...")
            self.train()
        else:
            try:
                _ = self.scaler.scale_
            except AttributeError:
                print("Model files exist but not loaded. Loading now...")
                self._load_model()
    
    def is_trained(self):
        """Check if model files exist"""
        model_exists = os.path.exists(os.path.join(self.model_dir, 'model.pkl'))
        scaler_exists = os.path.exists(os.path.join(self.model_dir, 'scaler.pkl'))
        return model_exists and scaler_exists
    
    def _generate_training_data(self, n_samples=5000):
        """Generate training data with better class separation"""
        np.random.seed(42)
        
        n_features = 20
        
        # Low threat (class 0) - 50% of data
        low_samples = int(n_samples * 0.5)
        low_data = np.random.normal(0, 1.5, (low_samples, n_features))
        low_labels = np.zeros(low_samples)
        
        # Medium threat (class 1) - 30% of data  
        medium_samples = int(n_samples * 0.3)
        medium_data = np.random.normal(4, 2, (medium_samples, n_features))
        medium_labels = np.ones(medium_samples)
        
        # High threat (class 2) - 20% of data
        high_samples = n_samples - low_samples - medium_samples
        high_data = np.random.normal(8, 2, (high_samples, n_features))
        # Make high threat features more distinctive
        high_data[:, [1, 6, 7]] += np.random.normal(5, 1, (high_samples, 3))
        high_labels = np.full(high_samples, 2)
        
        # Combine data
        X = np.vstack([low_data, medium_data, high_data])
        y = np.hstack([low_labels, medium_labels, high_labels])
        
        return X, y
    
    def _save_model(self):
        """Save trained model"""
        joblib.dump(self.model, os.path.join(self.model_dir, 'model.pkl'))
        joblib.dump(self.scaler, os.path.join(self.model_dir, 'scaler.pkl'))
        logger.info("Model and scaler saved successfully")
    
    def _load_model(self):
        """Load trained model"""
        try:
            model_path = os.path.join(self.model_dir, 'model.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                logger.info("Model and scaler loaded successfully")
                print("✅ Model and scaler loaded successfully")
            else:
                logger.warning("Model files not found, training new model...")
                self.train()
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            logger.info("Training new model...")
            self.train()
