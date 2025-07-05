import os
import shutil

def force_retrain():
    print("=== FORCING MODEL RETRAIN ===\n")
    
    # 1. Delete existing model files
    if os.path.exists('models'):
        shutil.rmtree('models')
        print("🗑️ Deleted old model files")
    
    # 2. Create fresh models directory
    os.makedirs('models', exist_ok=True)
    print("📁 Created fresh models directory")
    
    # 3. Test the training process
    print("\n🏋️ Testing model training...")
    
    try:
        import sys
        sys.path.append('src')
        
        from threat_classifier.models.threat_classifier import ThreatClassifier
        from threat_classifier.data.data_processor import DataProcessor
        
        # Initialize and train
        classifier = ThreatClassifier()
        print("✅ Classifier initialized")
        
        # Force training
        accuracy = classifier.train()
        print(f"✅ Model trained with accuracy: {accuracy:.4f}")
        
        # Test prediction
        data_processor = DataProcessor()
        test_logs = ["Failed login attempt from 192.168.1.100"]
        processed_data = data_processor.process_logs(test_logs)
        
        predictions = classifier.predict(processed_data)
        probabilities = classifier.predict_proba(processed_data)
        
        print(f"✅ Test prediction: {predictions[0]}")
        print(f"✅ Test probability: {probabilities[0].max():.4f}")
        
        print("\n🎉 Model training successful!")
        return True
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        return False

if __name__ == "__main__":
    success = force_retrain()
    
    if success:
        print("\n🚀 NEXT STEPS:")
        print("1. Stop your Flask app (Ctrl+C)")
        print("2. Restart it: python app.py")
        print("3. Try the analysis again")
    else:
        print("\n❌ Training failed. Check the error above.")