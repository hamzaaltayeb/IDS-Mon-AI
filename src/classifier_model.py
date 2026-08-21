from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

class AttackClassifier:
    """
    Module for supervised multi-class classification of network attacks.
    Classifies traffic into: Normal, DDoS, Brute Force, Port Scan.
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

    def save_model(self, path="models/classifier_model.joblib"):
        """
        Saves the trained model to a file.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        print(f"Classifier model saved to {path}")

    def load_model(self, path="models/classifier_model.joblib"):
        """
        Loads the model from a file.
        """
        if os.path.exists(path):
            self.model = joblib.load(path)
            print(f"Classifier model loaded from {path}")
        else:
            print(f"Error: Model file {path} not found.")

if __name__ == "__main__":
    classifier = AttackClassifier()
    print("Attack Classifier initialized.")
