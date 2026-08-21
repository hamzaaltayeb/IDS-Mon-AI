import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

class Preprocessor:
    """
    Module for cleaning, encoding, and normalizing network data.
    """
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.features_to_scale = [
            'proto', 'dst_port', 'total_size', 'avg_size', 'std_size', 
            'pkt_count', 'duration', 'avg_inter_arrival', 'max_inter_arrival',
            'packets_per_second', 'bytes_per_second'
        ]

    def preprocess(self, df, fit=False):
        """
        Cleans and scales data.
        """
        working_df = df.copy()

        # Handle missing values
        working_df = working_df.fillna(0)

        # Drop non-numeric identifiers for the AI model but keep them if needed for results
        # For training, we only need the numeric features
        X = working_df[self.features_to_scale]

        if fit:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        return X_scaled

    def encode_labels(self, labels, fit=False):
        """
        Encodes target labels (e.g., 'Normal', 'DDoS').
        """
        if 'target' not in self.label_encoders:
            self.label_encoders['target'] = LabelEncoder()
        
        if fit:
            return self.label_encoders['target'].fit_transform(labels)
        else:
            return self.label_encoders['target'].transform(labels)

if __name__ == "__main__":
    # Example usage
    try:
        features_df = pd.read_csv("data/flow_features.csv")
        preprocessor = Preprocessor()
        X_scaled = preprocessor.preprocess(features_df, fit=True)
        print("Data preprocessed successfully.")
        print(f"Shape: {X_scaled.shape}")
    except FileNotFoundError:
        print("Please run feature_extractor.py first.")
