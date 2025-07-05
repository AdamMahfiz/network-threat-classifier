import os
import shutil
import sys
sys.path.append('src')

def ultra_aggressive_fix():
    print("=== ULTRA-AGGRESSIVE HIGH THREAT DETECTION FIX ===\n")
    
    # Delete old model completely
    if os.path.exists('models'):
        shutil.rmtree('models')
        print("🗑️ Deleted old conservative model")
    
    os.makedirs('models', exist_ok=True)
    
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    import joblib
    
    print("🚀 Creating ULTRA-AGGRESSIVE threat detection model...")
    
    # EXTREME model parameters for high threat detection
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight={0: 1, 1: 3, 2: 10},  # HIGH threats get 10x weight!
        random_state=42,
        n_jobs=-1
    )
    
    scaler = StandardScaler()
    
    # Generate EXTREME training data based on your actual score ranges
    print("📊 Generating EXTREME training data...")
    
    np.random.seed(42)
    n_samples = 8000
    n_features = 20
    
    # LOW THREAT (30% of data) - scores 20-35
    low_samples = int(n_samples * 0.3)
    low_data = np.random.normal(25, 5, (low_samples, n_features))
    low_labels = np.zeros(low_samples)
    
    # MEDIUM THREAT (30% of data) - scores 35-50
    medium_samples = int(n_samples * 0.3)
    medium_data = np.random.normal(42, 6, (medium_samples, n_features))
    medium_labels = np.ones(medium_samples)
    
    # HIGH THREAT (40% of data) - scores 45+
    high_samples = n_samples - low_samples - medium_samples
    high_data = np.random.normal(60, 8, (high_samples, n_features))
    
    # Make HIGH threat features EXTREMELY distinctive
    high_data[:, [0, 1, 6, 7]] += np.random.normal(25, 4, (high_samples, 4))
    high_data[:, [2, 3, 4, 5]] += np.random.normal(20, 5, (high_samples, 4))
    high_data[:, [8, 9, 10]] += np.random.normal(15, 3, (high_samples, 3))
    
    high_labels = np.full(high_samples, 2)
    
    # Combine data
    X = np.vstack([low_data, medium_data, high_data])
    y = np.hstack([low_labels, medium_labels, high_labels])
    
    print(f"Training data: {low_samples} Low, {medium_samples} Medium, {high_samples} High")
    
    # Train model
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    model.fit(X_train_scaled, y_train)
    
    # Test model
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"✅ ULTRA-AGGRESSIVE model trained with accuracy: {accuracy:.4f}")
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Low', 'Medium', 'High']))
    
    # Save model
    joblib.dump(model, 'models/model.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    
    # Test with known high-threat logs
    from src.threat_classifier.data.data_processor import DataProcessor
    processor = DataProcessor()
    
    test_high_threats = [
        "[2023-05-23 10:51:33] DDoS attack signature detected from 10.0.0.15",
        "[2023-05-23 10:52:18] Malware signature detected in traffic from 172.16.0.20", 
        "[2023-05-23 10:53:45] SQL injection attempt blocked from 203.0.113.50",
        "[2023-05-23 10:54:12] Brute force attack on SSH port 22 from 203.0.113.15"
    ]
    
    test_medium_threats = [
        "[2023-05-23 10:46:15] Failed login for user admin from 192.168.1.10",
        "[2023-05-23 10:48:22] Port scan detected from 10.0.0.25",
        "[2023-05-23 10:49:45] Firewall blocked connection from 172.16.0.5"
    ]
    
    test_low_threats = [
        "[2023-05-23 10:45:32] Connection attempt from 192.168.1.5 to port 22",
        "[2023-05-23 10:47:03] Successful login for user user from 192.168.1.15",
        "[2023-05-23 10:55:33] Normal HTTP request to port 80"
    ]
    
    all_test_logs = test_high_threats + test_medium_threats + test_low_threats
    
    print("\n🧪 Testing ULTRA-AGGRESSIVE model:")
    print("=" * 80)
    
    processed_data = processor.process_logs(all_test_logs)
    predictions = model.predict(scaler.transform(processed_data))
    probabilities = model.predict_proba(scaler.transform(processed_data))
    
    threat_levels = ['Low', 'Medium', 'High']
    
    high_detected = 0
    medium_detected = 0
    
    print("🔴 HIGH THREAT TESTS:")
    for i, log in enumerate(test_high_threats):
        pred = predictions[i]
        prob = probabilities[i]
        level = threat_levels[int(pred)]
        confidence = prob.max()
        
        if level == 'High':
            high_detected += 1
            status = "✅"
        else:
            status = "❌"
        
        print(f"  {status} {level:6} ({confidence:.2f}) | {log}")
    
    print(f"\n🟡 MEDIUM THREAT TESTS:")
    for i, log in enumerate(test_medium_threats):
        pred = predictions[i + len(test_high_threats)]
        prob = probabilities[i + len(test_high_threats)]
        level = threat_levels[int(pred)]
        confidence = prob.max()
        
        if level in ['Medium', 'High']:
            medium_detected += 1
            status = "✅"
        else:
            status = "❌"
        
        print(f"  {status} {level:6} ({confidence:.2f}) | {log}")
    
    print(f"\n🟢 LOW THREAT TESTS:")
    for i, log in enumerate(test_low_threats):
        pred = predictions[i + len(test_high_threats) + len(test_medium_threats)]
        prob = probabilities[i + len(test_high_threats) + len(test_medium_threats)]
        level = threat_levels[int(pred)]
        confidence = prob.max()
        
        status = "✅" if level == 'Low' else "❌"
        print(f"  {status} {level:6} ({confidence:.2f}) | {log}")
    
    print(f"\n🎯 RESULTS:")
    print(f"   HIGH THREATS DETECTED: {high_detected}/4")
    print(f"   MEDIUM+ DETECTED: {medium_detected}/3")
    
    if high_detected >= 3:
        print("\n✅ SUCCESS! Model should now detect high threats!")
    else:
        print("\n⚠️  Still needs more aggressive tuning.")
    
    print("\n🔧 NEXT STEPS:")
    print("1. Stop Flask (Ctrl+C)")
    print("2. Run: python app.py")
    print("3. Upload test_logs.txt again")

if __name__ == "__main__":
    ultra_aggressive_fix()