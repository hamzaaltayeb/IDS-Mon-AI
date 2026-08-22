import os
import joblib
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "src", "models", "anomaly_model.joblib")

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

    def save_model(self, path=None):
        """
        Saves the trained model to a file.
        """
        target_path = path or DEFAULT_MODEL_PATH
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        joblib.dump(self.model, target_path)
        print(f"Anomaly model saved to {target_path}")

    def load_model(self, path=None):
        """
        Loads the model from a file.
        """
        target_path = path or DEFAULT_MODEL_PATH
        if os.path.exists(target_path):
            self.model = joblib.load(target_path)
            print(f"Anomaly model loaded from {target_path}")
        else:
            print(f"Error: Model file {target_path} not found.")


if __name__ == "__main__":
    # Example usage (needs preprocessed data)
    detector = AnomalyDetector()
    print("Anomaly Detector initialized.")
