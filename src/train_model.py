import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from feature_extractor import FeatureExtractor
from preprocessing import Preprocessor
from anomaly_model import AnomalyDetector
from classifier_model import AttackClassifier

def generate_synthetic_data(samples=2000):
    """
    Generates a synthetic network traffic dataset for training.
    In a real project, this would be replaced by a real PCAP or CSV dataset.
    """
    print("Generating synthetic network traffic dataset...")
    
    # Random Normal Traffic
    normal = pd.DataFrame({
        'proto': np.random.choice([6, 17], samples), # TCP/UDP
        'dst_port': np.random.choice([80, 443, 53, 22], samples),
        'total_size': np.random.randint(100, 10000, samples),
        'avg_size': np.random.randint(50, 500, samples),
        'std_size': np.random.randint(0, 100, samples),
        'pkt_count': np.random.randint(1, 50, samples),
        'duration': np.random.uniform(0.1, 10.0, samples),
        'avg_inter_arrival': np.random.uniform(0.01, 0.5, samples),
        'max_inter_arrival': np.random.uniform(0.1, 1.0, samples),
        'label': 'Normal'
    })

    # DDoS Attack (High packet count, low duration, high bytes/sec)
    ddos = pd.DataFrame({
        'proto': np.random.choice([6], samples // 4),
        'dst_port': 80,
        'total_size': np.random.randint(50000, 200000, samples // 4),
        'avg_size': np.random.randint(1000, 2000, samples // 4),
        'std_size': np.random.randint(100, 500, samples // 4),
        'pkt_count': np.random.randint(500, 2000, samples // 4),
        'duration': np.random.uniform(0.1, 1.0, samples // 4),
        'avg_inter_arrival': np.random.uniform(0.001, 0.01, samples // 4),
        'max_inter_arrival': np.random.uniform(0.01, 0.05, samples // 4),
        'label': 'DDoS'
    })

    # Port Scan (Many different ports, low packet count per flow)
    scan = pd.DataFrame({
        'proto': 6,
        'dst_port': np.random.randint(1, 65535, samples // 4),
        'total_size': np.random.randint(40, 200, samples // 4),
        'avg_size': np.random.randint(40, 60, samples // 4),
        'std_size': 0,
        'pkt_count': np.random.randint(1, 10, samples // 4),
        'duration': np.random.uniform(0.01, 0.1, samples // 4),
        'avg_inter_arrival': np.random.uniform(0.001, 0.05, samples // 4),
        'max_inter_arrival': np.random.uniform(0.01, 0.1, samples // 4),
        'label': 'Port Scan'
    })

    # Brute Force (Specific port like 22, medium packet count, regular intervals)
    brute = pd.DataFrame({
        'proto': 6,
        'dst_port': 22,
        'total_size': np.random.randint(1000, 5000, samples // 4),
        'avg_size': np.random.randint(100, 300, samples // 4),
        'std_size': np.random.randint(10, 50, samples // 4),
        'pkt_count': np.random.randint(50, 150, samples // 4),
        'duration': np.random.uniform(5.0, 30.0, samples // 4),
        'avg_inter_arrival': np.random.uniform(0.1, 0.5, samples // 4),
        'max_inter_arrival': np.random.uniform(0.5, 2.0, samples // 4),
        'label': 'Brute Force'
    })

    df = pd.concat([normal, ddos, scan, brute], ignore_index=True)
    
    # Calculate engineered features manually for synthetic data
    df['packets_per_second'] = df['pkt_count'] / (df['duration'] + 1e-6)
    df['bytes_per_second'] = df['total_size'] / (df['duration'] + 1e-6)
    
    return df

def main():
    # 1. Get Data
    df = generate_synthetic_data()
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    df.to_csv("data/synthetic_dataset.csv", index=False)
    
    # 2. Preprocess
    preprocessor = Preprocessor()
    X = preprocessor.preprocess(df, fit=True)
    y = preprocessor.encode_labels(df['label'], fit=True)
    
    # Save preprocessor for real-time use
    joblib.dump(preprocessor, "models/preprocessor.joblib")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Train Anomaly Detector (train only on 'Normal' or all data as contamination)
    # Usually IF is trained on all data with a contamination factor
    anomaly_detector = AnomalyDetector(contamination=0.25) # Approx 25% are attacks
    anomaly_detector.train(X_train)
    anomaly_detector.save_model("models/anomaly_model.joblib")
    
    # 4. Train Attack Classifier
    attack_classifier = AttackClassifier()
    attack_classifier.train(X_train, y_train)
    attack_classifier.evaluate(X_test, y_test)
    attack_classifier.save_model("models/classifier_model.joblib")
    
    print("\nTraining Phase Completed!")

if __name__ == "__main__":
    main()
