import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "src", "models", "classifier_model.joblib")

class AttackClassifier:
    """
    Module for supervised multi-class classification of network attacks.
    Classifies traffic into: Normal, DDoS, Brute Force, Port Scan, or UNSW-NB15 categories.
    """
    def __init__(self, n_estimators=100):
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=42)

    def train(self, X, y):
        """
        Trains the Random Forest classifier on labeled traffic data.
        """
        print("Training Attack Classifier (Random Forest)...")
        self.model.fit(X, y)

    def evaluate(self, X_test, y_test):
        """
        Evaluates the classifier and prints a report.
        """
        predictions = self.model.predict(X_test)
        print("Accuracy:", accuracy_score(y_test, predictions))
        print("\nClassification Report:\n", classification_report(y_test, predictions))

    def predict(self, X):
        """
        Predicts the attack class for given features.
        """
        return self.model.predict(X)

    def predict_proba(self, X):
        """
        Returns probability estimates for each class.
        """
        return self.model.predict_proba(X)

    def save_model(self, path=None):
        """
        Saves the trained model to a file.
        """
        target_path = path or DEFAULT_MODEL_PATH
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        joblib.dump(self.model, target_path)
        print(f"Classifier model saved to {target_path}")

    def load_model(self, path=None):
        """
        Loads the model from a file.
        """
        target_path = path or DEFAULT_MODEL_PATH
        if os.path.exists(target_path):
            self.model = joblib.load(target_path)
            print(f"Classifier model loaded from {target_path}")
        else:
            print(f"Error: Model file {target_path} not found.")


if __name__ == "__main__":
    classifier = AttackClassifier()
    print("Attack Classifier initialized.")
