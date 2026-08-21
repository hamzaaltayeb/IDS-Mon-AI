from sklearn.ensemble import IsolationForest
import joblib
import os

class AnomalyDetector:
    """
    Module for unsupervised anomaly detection using Isolation Forest.
    Detects unknown attacks or suspicious deviations from normal traffic.
    """
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)

    def train(self, X):
        """
        Trains the Isolation Forest model on normal traffic features.
        """
        print("Training Anomaly Detector (Isolation Forest)...")
        self.model.fit(X)

    def predict(self, X):
        """
        Predicts if traffic is normal (1) or an anomaly (-1).
        """
        # Isolation Forest returns 1 for inliers (normal) and -1 for outliers (anomaly)
        return self.model.predict(X)

    def save_model(self, path="models/anomaly_model.joblib"):
        """
        Saves the trained model to a file.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        print(f"Anomaly model saved to {path}")

    def load_model(self, path="models/anomaly_model.joblib"):
        """
        Loads the model from a file.
        """
        if os.path.exists(path):
            self.model = joblib.load(path)
            print(f"Anomaly model loaded from {path}")
        else:
            print(f"Error: Model file {path} not found.")

if __name__ == "__main__":
    # Example usage (needs preprocessed data)
    detector = AnomalyDetector()
    print("Anomaly Detector initialized.")
