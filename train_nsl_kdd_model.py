"""
Train model on NSL-KDD dataset
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import logging
import argparse
import shutil
import glob
from sklearn.preprocessing import StandardScaler, LabelEncoder

sys.path.append('src')
from src.threat_classifier.data.nsl_kdd_processor import NSLKDDProcessor
from src.threat_classifier.utils.logger import setup_logger

# Setup logging
logger = setup_logger('nsl_kdd_trainer', 'logs/nsl_kdd_training.log')

def extract_nsl_kdd_dataset():
    """Extract and prepare NSL-KDD dataset from existing folder"""
    print("Checking for NSL-KDD dataset...")
    
    # Check if data/nsl-kdd directory exists
    nsl_kdd_dir = 'data/nsl-kdd'
    if not os.path.exists(nsl_kdd_dir):
        print(f"Creating directory: {nsl_kdd_dir}")
        os.makedirs(nsl_kdd_dir, exist_ok=True)
    
    # Look for NSL-KDD files in various locations
    possible_locations = [
        'data/nsl-kdd/',
        'data/nsl_kdd/',
        'nsl-kdd/',
        'nsl_kdd/',
        'data/',
        '.'
    ]
    
    found_files = []
    for location in possible_locations:
        if os.path.exists(location):
            # Look for NSL-KDD files
            patterns = [
                'KDDTrain*.txt',
                'KDDTrain*.arff',
                'KDDTest*.txt', 
                'KDDTest*.arff'
            ]
            
            for pattern in patterns:
                files = glob.glob(os.path.join(location, pattern))
                found_files.extend(files)
    
    if not found_files:
        print("No NSL-KDD files found!")
        print("Please ensure you have the NSL-KDD dataset files in one of these locations:")
        print("- data/nsl-kdd/")
        print("- data/nsl_kdd/") 
        print("- nsl-kdd/")
        print("- nsl_kdd/")
        print("- data/")
        print("- Current directory")
        return False
    
    print(f"Found {len(found_files)} NSL-KDD files:")
    for file in found_files:
        print(f"  - {file}")
    
    # Copy files to data/nsl-kdd directory
    print("\nOrganizing files in data/nsl-kdd/ directory...")
    for file_path in found_files:
        filename = os.path.basename(file_path)
        dest_path = os.path.join(nsl_kdd_dir, filename)
        
        if not os.path.exists(dest_path):
            shutil.copy2(file_path, dest_path)
            print(f"  Copied: {filename}")
        else:
            print(f"  Already exists: {filename}")
    
    # Convert ARFF files to TXT if needed
    arff_files = glob.glob(os.path.join(nsl_kdd_dir, '*.arff'))
    for arff_file in arff_files:
        txt_file = arff_file.replace('.arff', '.txt')
        if not os.path.exists(txt_file):
            print(f"Converting {os.path.basename(arff_file)} to TXT format...")
            convert_arff_to_txt(arff_file, txt_file)
    
    print("NSL-KDD dataset preparation completed!")
    return True

def convert_arff_to_txt(arff_file, txt_file):
    """Convert ARFF file to TXT format"""
    try:
        with open(arff_file, 'r') as f:
            lines = f.readlines()
        
        # Find data section
        data_start = False
        data_lines = []
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('@data'):
                data_start = True
                continue
            elif line.startswith('@'):
                continue
            elif data_start and line:
                data_lines.append(line)
        
        # Write to TXT file
        with open(txt_file, 'w') as f:
            for line in data_lines:
                f.write(line + '\n')
        
        print(f"  Converted: {os.path.basename(arff_file)} → {os.path.basename(txt_file)}")
        
    except Exception as e:
        print(f"  Error converting {arff_file}: {e}")

def find_best_training_file():
    """Find the best available training file"""
    nsl_kdd_dir = 'data/nsl-kdd'
    training_files = [
        'KDDTrain+.txt',
        'KDDTrain+_20Percent.txt',
        'KDDTrain+.arff',
        'KDDTrain+_20Percent.arff'
    ]
    
    for file in training_files:
        file_path = os.path.join(nsl_kdd_dir, file)
        if os.path.exists(file_path):
            return file_path
    
    return None

def find_best_test_file():
    """Find the best available test file"""
    nsl_kdd_dir = 'data/nsl-kdd'
    test_files = [
        'KDDTest+.txt',
        'KDDTest-21.txt',
        'KDDTest+.arff',
        'KDDTest-21.arff'
    ]
    
    for file in test_files:
        file_path = os.path.join(nsl_kdd_dir, file)
        if os.path.exists(file_path):
            return file_path
    
    return None

def train_model(train_file=None, test_file=None):
    # Extract dataset first
    if not extract_nsl_kdd_dataset():
        return False
    
    # Find best available files if not specified
    if train_file is None:
        train_file = find_best_training_file()
        if train_file is None:
            print("Error: No training file found!")
            print("Available files in data/nsl-kdd/:")
            if os.path.exists('data/nsl-kdd'):
                for file in os.listdir('data/nsl-kdd'):
                    print(f"  - {file}")
            return False
    
    if test_file is None:
        test_file = find_best_test_file()
        if test_file is None:
            print("Warning: No test file found, will use train/test split")
    
    MODEL_PATH = 'models/nsl_kdd_model.pkl'
    PROCESSOR_PATH = 'models/nsl_kdd_processor.pkl'
    
    # Check if training data exists
    if not os.path.exists(train_file):
        print(f"Error: Training data not found at {train_file}")
        print("Please ensure you have the NSL-KDD dataset in the correct directory")
        print("Usage: python train_nsl_kdd_model.py <train_file> [test_file]")
        return False
    
    try:
        # Load training data
        print(f'Loading NSL-KDD training data from {train_file}...')
        df = pd.read_csv(train_file, names=NSLKDDProcessor().feature_names + ['label'], index_col=False)
        print(f'Training samples: {len(df)}')
        
        # Check for missing values
        if df.isnull().any().any():
            print("Warning: Found missing values in dataset. Filling with 0...")
            df = df.fillna(0)
        
        # Prepare processor and fit
        print('Fitting NSLKDDProcessor...')
        processor = NSLKDDProcessor()
        processor.fit(df)
        features = processor.transform(df)
        
        # Create 3-class labels (0=Low, 1=Medium, 2=High)
        labels = df['label'].apply(processor.get_threat_level).values
        
        print(f'Feature matrix shape: {features.shape}')
        print(f'Label distribution: {pd.Series(labels).value_counts().to_dict()}')
        
        # Split data for evaluation if no test file provided
        if test_file is None or not os.path.exists(test_file):
            print(f'Test file not found, using train/test split...')
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.2, random_state=42, stratify=labels
            )
        else:
            print(f'Loading test data from {test_file}...')
            # Load separate test file
            test_df = pd.read_csv(test_file, names=NSLKDDProcessor().feature_names + ['label'], index_col=False)
            if test_df.isnull().any().any():
                test_df = test_df.fillna(0)
            
            X_train = features
            y_train = labels
            X_test = processor.transform(test_df)
            y_test = (test_df['label'] != 'normal').astype(int)
            print(f'Test samples: {len(test_df)}')
        
        # Train model
        print('Training LogisticRegression model...')
        model = LogisticRegression(max_iter=500, solver='lbfgs', random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate model
        print('\nModel Evaluation:')
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f'Accuracy: {accuracy:.4f}')
        print('\nClassification Report:')
        print(classification_report(y_test, y_pred, labels=[0,1,2], target_names=['Low', 'Medium', 'High']))
        
        # Save processor and model
        os.makedirs('models', exist_ok=True)
        joblib.dump(processor, PROCESSOR_PATH)
        joblib.dump(model, MODEL_PATH)
        
        print(f'\nModel saved to {MODEL_PATH}')
        print(f'Processor saved to {PROCESSOR_PATH}')
        print('Training completed successfully!')
        
        return True
        
    except Exception as e:
        print(f"Error during training: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Train NSL-KDD threat classification model')
    parser.add_argument('train_file', nargs='?', help='Path to training data file (auto-detected if not provided)')
    parser.add_argument('test_file', nargs='?', help='Path to test data file (auto-detected if not provided)')
    parser.add_argument('--extract-only', action='store_true', help='Only extract dataset, do not train')
    
    args = parser.parse_args()
    
    if args.extract_only:
        success = extract_nsl_kdd_dataset()
    else:
        success = train_model(args.train_file, args.test_file)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main() 