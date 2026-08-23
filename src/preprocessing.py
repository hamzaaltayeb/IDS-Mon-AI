import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The standard numerical features of the 11-feature flow representation
FLOW_NUMERIC_FEATURES = [
    'total_flow_size',
    'average_packet_size',
    'std_packet_size',
    'packet_count',
    'flow_duration',
    'average_inter_arrival_time',
    'maximum_inter_arrival_time',
    'packets_per_second',
    'bytes_per_second'
]

# Legacy compatibility list
UNSW_NUMERIC_FEATURES = FLOW_NUMERIC_FEATURES

class Preprocessor:
    """
    Module for cleaning, encoding, and normalizing network flow features.
    """
    def __init__(self, features=None):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.features_to_scale = features or FLOW_NUMERIC_FEATURES

    def preprocess(self, df, fit=False):
        """
        Cleans and scales data.
        """
        working_df = df.copy()

        # Ensure all required features are present
        for col in self.features_to_scale:
            if col not in working_df.columns:
                working_df[col] = 0.0

        # Handle missing values & infinities
        working_df[self.features_to_scale] = working_df[self.features_to_scale].replace([np.inf, -np.inf], 0.0).fillna(0.0)

        X = working_df[self.features_to_scale]

        if fit:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        return X_scaled

    def encode_labels(self, labels, fit=False):
        """
        Encodes target labels (e.g., 'Normal', 'DDoS', 'Port Scan', 'Brute Force').
        """
        if 'target' not in self.label_encoders:
            self.label_encoders['target'] = LabelEncoder()
        
        if fit:
            return self.label_encoders['target'].fit_transform(labels)
        else:
            return self.label_encoders['target'].transform(labels)

    def decode_labels(self, encoded_labels):
        """
        Decodes numeric predictions back to original string labels.
        """
        if 'target' in self.label_encoders:
            return self.label_encoders['target'].inverse_transform(encoded_labels)
        return [str(l) for l in encoded_labels]
