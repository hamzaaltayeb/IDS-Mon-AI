import time
import pandas as pd
import numpy as np
import joblib
import os
from preprocessing import Preprocessor
from alerts import AlertSystem

class RealTimeMonitor:
    """
    Simulation of a real-time network monitoring system.
    Reads "live" data snapshots, processes them, and detects threats.
    """
    def __init__(self, model_dir="models"):
        print("Initializing Real-Time Monitoring System...")
        try:
            self.preprocessor = joblib.load(f"{model_dir}/preprocessor.joblib")
            self.anomaly_model = joblib.load(f"{model_dir}/anomaly_model.joblib")
            self.classifier_model = joblib.load(f"{model_dir}/classifier_model.joblib")
            self.alert_system = AlertSystem()
            print("Models loaded successfully.")
        except Exception as e:
            print(f"Error loading models: {e}. Please run train_model.py first.")
            exit(1)

    def simulate_traffic(self):
        """
        Simulates a batch of fresh network traffic.
        """
        # We'll pick some random rows from our synthetic dataset if it exists, 
        # or create a few new ones on the fly.
        try:
            df = pd.read_csv("data/synthetic_dataset.csv")
            sample = df.sample(5) # Simulate 5 flows at a time
            return sample
        except FileNotFoundError:
            print("Synthetic dataset not found. Please train models first.")
            return pd.DataFrame()

    def monitor(self, iterations=10, interval=2):
        """
        Runs the monitoring loop.
        """
        print(f"Starting monitoring loop ({iterations} iterations)...")
        for i in range(iterations):
            print(f"\n--- Monitoring Cycle {i+1} ---")
            
            # 1. Get live traffic
            traffic_df = self.simulate_traffic()
            if traffic_df.empty: break
            
            # Add dummy IP addresses for identification
            traffic_df['src_ip'] = [f"192.168.1.{np.random.randint(2, 254)}" for _ in range(len(traffic_df))]
            
            # 2. Preprocess
            X_scaled = self.preprocessor.preprocess(traffic_df)
            
            # 3. Detect Anomalies (Unsupervised)
            anomalies = self.anomaly_model.predict(X_scaled)
            
            # 4. Classify Attacks (Supervised)
            attack_classes = self.classifier_model.predict(X_scaled)
            # Revert numeric labels back to strings
            attack_names = self.preprocessor.label_encoders['target'].inverse_transform(attack_classes)
            
            # 5. Alerting
            for idx, (anomaly, attack_name) in enumerate(zip(anomalies, attack_names)):
                ip = traffic_df.iloc[idx]['src_ip']
                
                # We alert if either the anomaly detector flags it OR the classifier calls it an attack
                if anomaly == -1 or attack_name != 'Normal':
                    # If classifier says Normal but Anomaly says -1, it's an "Unknown" threat
                    display_attack = attack_name if attack_name != 'Normal' else 'Unknown'
                    self.alert_system.trigger_alert(ip, display_attack)
                else:
                    print(f"Traffic from {ip}: Normal")
            
            time.sleep(interval)
        
        print("\nMonitoring simulation completed.")

if __name__ == "__main__":
    monitor = RealTimeMonitor()
    monitor.monitor()
