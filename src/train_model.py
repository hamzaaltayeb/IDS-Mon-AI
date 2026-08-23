import os
import sys
import pandas as pd
import numpy as np
import joblib

# Add src to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from preprocessing import Preprocessor, FLOW_NUMERIC_FEATURES
from anomaly_model import AnomalyDetector
from classifier_model import AttackClassifier

# Mapping UNSW-NB15 attack categories to the target project scope:
ATTACK_MAPPING = {
    'Normal': 'Normal',
    'DoS': 'DDoS',
    'Reconnaissance': 'Port Scan',
    'Exploits': 'Brute Force',
    'Backdoor': 'Brute Force'
}

def extract_flow_features_from_benchmark(df):
    """
    Transforms UNSW-NB15 packet summary columns into the exact 11 standard flow features.
    """
    f_df = pd.DataFrame()
    dur = df['dur'].clip(lower=1e-5)
    pkts = (df['spkts'] + df['dpkts']).clip(lower=1)
    bytes_tot = (df['sbytes'] + df['dbytes']).clip(lower=0)
    
    f_df['total_flow_size'] = bytes_tot
    f_df['average_packet_size'] = bytes_tot / pkts
    f_df['std_packet_size'] = ((df['sjit'] + df['djit']) / 2.0).clip(lower=0)
    f_df['packet_count'] = pkts
    f_df['flow_duration'] = dur
    f_df['average_inter_arrival_time'] = ((df['sinpkt'] + df['dinpkt']) / 2000.0).clip(lower=0)
    f_df['maximum_inter_arrival_time'] = (np.maximum(df['sinpkt'], df['dinpkt']) / 1000.0).clip(lower=0)
    f_df['packets_per_second'] = pkts / dur
    f_df['bytes_per_second'] = bytes_tot / dur
    return f_df

def load_and_prepare_dataset(file_path):
    """
    Loads UNSW-NB15 dataset and maps attack categories to the target classes:
    [Normal, DDoS, Port Scan, Brute Force].
    """
    print(f"Loading benchmark dataset from: {file_path}...")
    df = pd.read_csv(file_path)
    df['attack_label'] = df['attack_cat'].map(ATTACK_MAPPING).fillna('Unknown')
    
    # Filter for target classes (Normal is preserved as first-class citizen)
    filtered_df = df[df['attack_label'] != 'Unknown'].copy().reset_index(drop=True)
    print(f"Dataset records ({len(filtered_df)}) across classes:")
    print(filtered_df['attack_label'].value_counts().to_string())
    
    X_df = extract_flow_features_from_benchmark(filtered_df)
    y_labels = filtered_df['attack_label']
    return X_df, y_labels

def save_models_and_preprocessor(preprocessor, anomaly_detector, attack_classifier):
    dest_dirs = [
        os.path.join(BASE_DIR, "models"),
        os.path.join(SRC_DIR, "models")
    ]
    for d in dest_dirs:
        os.makedirs(d, exist_ok=True)
        joblib.dump(preprocessor, os.path.join(d, "preprocessor.joblib"))
        anomaly_detector.save_model(os.path.join(d, "anomaly_model.joblib"))
        attack_classifier.save_model(os.path.join(d, "classifier_model.joblib"))
    print("All models and preprocessors saved successfully.")

def main():
    train_path = os.path.join(SRC_DIR, "data", "UNSW_NB15_training-set.csv")
    test_path = os.path.join(SRC_DIR, "data", "UNSW_NB15_testing-set.csv")
    
    if not os.path.exists(train_path):
        print(f"Error: Dataset file not found at {train_path}")
        sys.exit(1)
        
    print("=========================================================")
    print("🚀 Training AI Models on Standard 11 Flow Features")
    print("=========================================================")
    
    # 1. Load Data
    X_train_df, y_train_labels = load_and_prepare_dataset(train_path)
    X_test_df, y_test_labels = load_and_prepare_dataset(test_path) if os.path.exists(test_path) else (None, None)
    
    # 2. Preprocessing & Scaling
    preprocessor = Preprocessor(features=FLOW_NUMERIC_FEATURES)
    X_train = preprocessor.preprocess(X_train_df, fit=True)
    y_train = preprocessor.encode_labels(y_train_labels, fit=True)
    
    if X_test_df is not None:
        X_test = preprocessor.preprocess(X_test_df, fit=False)
        y_test = preprocessor.encode_labels(y_test_labels, fit=False)
    else:
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
    
    # 3. Train Isolation Forest (Unsupervised Anomaly Detection on Normal baseline)
    normal_indices = (y_train_labels == 'Normal').values
    X_normal = X_train[normal_indices]
    print(f"\nTraining Isolation Forest on Normal baseline ({len(X_normal)} samples)...")
    anomaly_detector = AnomalyDetector(contamination=0.03)
    anomaly_detector.train(X_normal)
    
    # 4. Train Random Forest (Multi-Class Classifier)
    print("\nTraining Random Forest Multi-Class Classifier...")
    attack_classifier = AttackClassifier(n_estimators=100)
    attack_classifier.train(X_train, y_train)
    
    # 5. Evaluate
    print("\n=========================================================")
    print("📊 Evaluation Results on Benchmark Testing Set:")
    print("=========================================================")
    attack_classifier.evaluate(X_test, y_test)
    
    # 6. Save Artifacts
    save_models_and_preprocessor(preprocessor, anomaly_detector, attack_classifier)
    print("\n✅ Flow Feature AI Model Training Completed Successfully!")

if __name__ == "__main__":
    main()
