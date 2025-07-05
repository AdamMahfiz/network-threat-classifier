"""
NSL-KDD Dataset Processor
Handles preprocessing and feature extraction for NSL-KDD dataset
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from typing import Tuple, List

class NSLKDDProcessor:
    """Process NSL-KDD dataset features"""
    
    def __init__(self):
        self.protocol_encoder = LabelEncoder()
        self.service_encoder = LabelEncoder()
        self.flag_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # NSL-KDD feature names
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        
        # Attack categories mapping
        self.attack_categories = {
            'normal': 0,
            'neptune': 1, 'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,  # DoS
            'mailbomb': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1, 'apache2': 1,
            'buffer_overflow': 2, 'loadmodule': 2, 'perl': 2, 'rootkit': 2,  # Exploits
            'xterm': 2, 'sqlattack': 2, 'httptunnel': 2, 'ps': 2,
            'guess_passwd': 3, 'ftp_write': 3, 'imap': 3, 'phf': 3, 'multihop': 3,  # Probing
            'warezmaster': 3, 'warezclient': 3, 'spy': 3, 'portsweep': 3, 'ipsweep': 3,
            'nmap': 3, 'satan': 3, 'mscan': 3, 'saint': 3,
            'snmpgetattack': 4, 'named': 4, 'sendmail': 4, 'snmpguess': 4,  # R2L
            'worm': 4, 'httptunnel': 4, 'mailbomb': 4, 'apache2': 4, 'processtable': 4,
            'udpstorm': 4, 'xlock': 4, 'xsnoop': 4, 'sendmail': 4, 'named': 4,
            'smurf': 4, 'mscan': 4, 'saint': 4, 'ftp_write': 4, 'guess_passwd': 4,
            'imap': 4, 'phf': 4, 'multihop': 4, 'warezmaster': 4, 'warezclient': 4,
            'spy': 4, 'portsweep': 4, 'ipsweep': 4, 'nmap': 4, 'satan': 4
        }
        
        # Threat level mapping (0: Low, 1: Medium, 2: High)
        self.threat_levels = {
            0: 0,  # Normal -> Low
            1: 1,  # DoS -> Medium
            2: 2,  # Exploits -> High
            3: 1,  # Probing -> Medium
            4: 2   # R2L -> High
        }
    
    def fit(self, df: pd.DataFrame) -> None:
        """Fit encoders and scaler on training data"""
        # Fit categorical encoders
        self.protocol_encoder.fit(df['protocol_type'])
        self.service_encoder.fit(df['service'])
        self.flag_encoder.fit(df['flag'])
        
        # Transform and scale numerical features
        numerical_features = self._get_numerical_features(df)
        self.scaler.fit(numerical_features)
        
        self.is_fitted = True
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform NSL-KDD data into feature matrix"""
        if not self.is_fitted:
            raise ValueError("Processor must be fitted before transform")
        
        # Encode categorical features
        protocol_encoded = self.protocol_encoder.transform(df['protocol_type'])
        service_encoded = self.service_encoder.transform(df['service'])
        flag_encoded = self.flag_encoder.transform(df['flag'])
        
        # Get numerical features
        numerical_features = self._get_numerical_features(df)
        
        # Scale numerical features
        numerical_scaled = self.scaler.transform(numerical_features)
        
        # Combine all features
        features = np.column_stack([
            numerical_scaled,
            protocol_encoded.reshape(-1, 1),
            service_encoded.reshape(-1, 1),
            flag_encoded.reshape(-1, 1)
        ])
        
        return features
    
    def _get_numerical_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract numerical features from dataframe"""
        numerical_cols = [
            'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        return df[numerical_cols].values
    
    def get_threat_level(self, attack_type: str) -> int:
        """Convert attack type to threat level"""
        attack_category = self.attack_categories.get(attack_type.lower(), 0)
        return self.threat_levels[attack_category]
    
    def process_csv(self, filepath: str) -> Tuple[np.ndarray, np.ndarray]:
        """Process NSL-KDD CSV file and return features and labels"""
        # Read CSV file with correct column names
        df = pd.read_csv(filepath, names=self.feature_names + ['label'], index_col=False, skipinitialspace=True)
        
        # Clean up the label column (remove any whitespace)
        df['label'] = df['label'].str.strip()
        
        # Extract labels
        labels = df['label'].apply(self.get_threat_level).values
        
        # Remove label column
        df = df.drop('label', axis=1)
        
        # Transform features
        features = self.transform(df)
        
        return features, labels 