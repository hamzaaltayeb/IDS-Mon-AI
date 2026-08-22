import os
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Standard numerical features from the real UNSW-NB15 benchmark dataset
UNSW_NUMERIC_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean'
]

class Preprocessor:
    """
    Module for cleaning, encoding, and normalizing real network dataset features.
    """
    def __init__(self, features=None):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.features_to_scale = features or UNSW_NUMERIC_FEATURES


    def preprocess(self, df, fit=False):
        """
        Cleans and scales data.
        """
        working_df = df.copy()

        # Ensure all required features are present
        for col in self.features_to_scale:
            if col not in working_df.columns:
                working_df[col] = 0

        # Handle missing values
        working_df[self.features_to_scale] = working_df[self.features_to_scale].fillna(0)

        X = working_df[self.features_to_scale]

        if fit:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        return X_scaled

    def encode_labels(self, labels, fit=False):
        """
        Encodes target labels (e.g., 'Normal', 'DDoS', 'Exploits').
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

if __name__ == "__main__":
    # Example usage
    flow_features_file = os.path.join(BASE_DIR, "data", "flow_features.csv")
    try:
        features_df = pd.read_csv(flow_features_file)
        preprocessor = Preprocessor()
        X_scaled = preprocessor.preprocess(features_df, fit=True)
        print("Data preprocessed successfully.")
        print(f"Shape: {X_scaled.shape}")
    except FileNotFoundError:
        print(f"Please run feature_extractor.py first to generate {flow_features_file}")

