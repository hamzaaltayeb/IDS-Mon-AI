import os
import sys
import pandas as pd
import numpy as np
import joblib

# Add src to sys.path to allow imports from anywhere
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from preprocessing import Preprocessor, UNSW_NUMERIC_FEATURES
from anomaly_model import AnomalyDetector
from classifier_model import AttackClassifier

# Mapping UNSW-NB15 attack categories to the project's target threat taxonomy
ATTACK_MAPPING = {
    'Normal': 'Normal',
    'DoS': 'DDoS',
    'Reconnaissance': 'Port Scan',
    'Exploits': 'Brute Force',
    'Backdoor': 'Brute Force',
    'Generic': 'Brute Force'
}

def load_and_prepare_dataset(file_path):
    """
    Loads real UNSW-NB15 dataset and maps attack categories to the target project scope:
    [Normal, DDoS, Port Scan, Brute Force].
    """
    print(f"Loading real benchmark dataset from: {file_path}...")
    df = pd.read_csv(file_path)
    
    # Map to target project classes (Normal, DDoS, Port Scan, Brute Force)
    df['attack_label'] = df['attack_cat'].map(ATTACK_MAPPING).fillna('Unknown')
    
    # Filter for the target attack classes
    filtered_df = df[df['attack_label'] != 'Unknown'].copy().reset_index(drop=True)
    print(f"Dataset loaded: {len(filtered_df)} records across classes:")
    print(filtered_df['attack_label'].value_counts().to_string())
    return filtered_df

def save_models_and_preprocessor(preprocessor, anomaly_detector, attack_classifier):
    """
    Saves trained models and preprocessor to both root models/ and src/models/.
    """
    dest_dirs = [
        os.path.join(BASE_DIR, "models"),
        os.path.join(SRC_DIR, "models")
    ]
    for d in dest_dirs:
        os.makedirs(d, exist_ok=True)
        joblib.dump(preprocessor, os.path.join(d, "preprocessor.joblib"))
        anomaly_detector.save_model(os.path.join(d, "anomaly_model.joblib"))
        attack_classifier.save_model(os.path.join(d, "classifier_model.joblib"))
    print("All models and preprocessors saved successfully to models/ and src/models/.")

def main():
    train_path = os.path.join(SRC_DIR, "data", "UNSW_NB15_training-set.csv")
    test_path = os.path.join(SRC_DIR, "data", "UNSW_NB15_testing-set.csv")
    
    if not os.path.exists(train_path):
        print(f"Error: Real dataset file not found at {train_path}")
        sys.exit(1)
        
    print("=========================================================")
    print("🚀 Training AI Models on Real UNSW-NB15 Benchmark Dataset")
    print("=========================================================")
    
    # 1. Load Real Data
    train_df = load_and_prepare_dataset(train_path)
    test_df = load_and_prepare_dataset(test_path) if os.path.exists(test_path) else None
    
    # 2. Feature Selection & Preprocessing
    available_features = [f for f in UNSW_NUMERIC_FEATURES if f in train_df.columns]
    preprocessor = Preprocessor(features=available_features)
    
    X_train = preprocessor.preprocess(train_df, fit=True)
    y_train = preprocessor.encode_labels(train_df['attack_label'], fit=True)
    
    if test_df is not None:
        X_test = preprocessor.preprocess(test_df, fit=False)
        y_test = preprocessor.encode_labels(test_df['attack_label'], fit=False)
    else:
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
    
    # 3. Train Isolation Forest (Unsupervised Anomaly Detection)
    attack_ratio = float((train_df['attack_label'] != 'Normal').mean())
    contamination = min(0.5, max(0.01, round(attack_ratio, 2)))
    print(f"\nTraining Isolation Forest (Contamination: {contamination:.2f})...")
    anomaly_detector = AnomalyDetector(contamination=contamination)
    anomaly_detector.train(X_train)
    
    # 4. Train Random Forest (Supervised Attack Classifier)
    print("\nTraining Random Forest Multi-Class Classifier...")
    attack_classifier = AttackClassifier(n_estimators=100)
    attack_classifier.train(X_train, y_train)
    
    # 5. Evaluate on Real Testing Set
    print("\n=========================================================")
    print("📊 Evaluation Results on Real Benchmark Testing Set:")
    print("=========================================================")
    attack_classifier.evaluate(X_test, y_test)
    
    # 6. Save Model Artifacts
    save_models_and_preprocessor(preprocessor, anomaly_detector, attack_classifier)
    print("\n✅ Real Benchmark Model Training Pipeline Completed Successfully!")

if __name__ == "__main__":
    main()


