import joblib
import pandas as pd
import numpy as np

# Load the model and processor
model = joblib.load('models/nsl_kdd_model.pkl')
processor = joblib.load('models/nsl_kdd_processor.pkl')

# Load a small sample of NSL-KDD data
data_path = 'data/nsl_kdd/KDDTest+.txt'

# NSL-KDD column names
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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]

# Read first 10 rows
df = pd.read_csv(data_path, names=nsl_kdd_columns, nrows=10)
print(f"Loaded {len(df)} rows from NSL-KDD test data")

# Remove label column for processing
df_features = df.drop('label', axis=1)

# Transform features
features = processor.transform(df_features)
print(f"Features shape: {features.shape}")

# Make predictions
predictions = model.predict(features)
print(f"Predictions: {predictions}")

# Check unique predictions
unique_preds = np.unique(predictions)
print(f"Unique predictions: {unique_preds}")

# Show first few rows with predictions
for i in range(min(5, len(df))):
    print(f"Row {i}: Actual: {df.iloc[i]['label']} -> Predicted: {predictions[i]}") 