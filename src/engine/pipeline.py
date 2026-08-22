import os
import sys
import numpy as np
import pandas as pd
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from preprocessing import Preprocessor, UNSW_NUMERIC_FEATURES
from database.models import NetworkFlow, Detection, Alert
from .feature_adapter import FeatureCompatibilityAdapter

class AIDetectionPipeline:
    _instance = None

    def __init__(self):
        self.preprocessor = None
        self.anomaly_model = None
        self.classifier_model = None
        self.load_models()

    def load_models(self):
        model_dirs = [
            os.path.join(BASE_DIR, "models"),
            os.path.join(SRC_DIR, "models")
        ]
        for d in model_dirs:
            p_prep = os.path.join(d, "preprocessor.joblib")
            p_anom = os.path.join(d, "anomaly_model.joblib")
            p_clf = os.path.join(d, "classifier_model.joblib")
            if os.path.exists(p_prep) and os.path.exists(p_anom) and os.path.exists(p_clf):
                try:
                    self.preprocessor = joblib.load(p_prep)
                    self.anomaly_model = joblib.load(p_anom)
                    self.classifier_model = joblib.load(p_clf)
                    print(f"AI Detection Pipeline loaded models from: {d}")
                    return True
                except Exception as e:
                    print(f"Error loading models from {d}: {e}")
        print("Warning: Trained AI models not found. Running with baseline heuristic fallback.")
        return False

    def calculate_threat_metrics(self, attack_type, confidence=1.0):
        """
        Threat Scoring Matrix:
        - Normal: 0 (LOW)
        - Unknown: 50 (MEDIUM)
        - Port Scan: 70 (HIGH)
        - Brute Force: 85 (HIGH)
        - DDoS: 95 (CRITICAL)
        """
        score_matrix = {
            'NORMAL': (0, 'LOW'),
            'UNKNOWN': (50, 'MEDIUM'),
            'PORT_SCAN': (70, 'HIGH'),
            'BRUTE_FORCE': (85, 'HIGH'),
            'DDOS': (95, 'CRITICAL')
        }
        base_score, severity = score_matrix.get(attack_type.upper(), (50, 'MEDIUM'))
        if attack_type.upper() == 'NORMAL':
            return 0, 'LOW'
        final_score = min(100, max(20, int(base_score * max(0.5, confidence))))
        return final_score, severity

    def generate_indicators(self, flow_dict, attack_type, threat_score):
        """
        Generates human-readable forensic indicators explaining why the flow was flagged.
        """
        indicators = []
        pps = flow_dict.get('packets_per_second', 0)
        bps = flow_dict.get('bytes_per_second', 0)
        port = flow_dict.get('destination_port', 0)
        pkt_count = flow_dict.get('packet_count', 0)
        duration = flow_dict.get('flow_duration', 0)

        if attack_type == 'DDOS':
            indicators.append(f"Volumetric flood signature detected: packet rate {pps:.1f} pkt/s, byte rate {bps/1024:.1f} KB/s")
            indicators.append(f"Excessive burst of {pkt_count} packets within short duration ({duration:.2f}s) targeting port {port}")
        elif attack_type == 'PORT_SCAN':
            indicators.append(f"Reconnaissance probing pattern on destination port {port}")
            indicators.append(f"Small flow payload ({pkt_count} packets) characteristic of rapid SYN/TCP port sweeping")
        elif attack_type == 'BRUTE_FORCE':
            indicators.append(f"Repeated authentication access pattern on service port {port}")
            indicators.append(f"High-frequency credential handshake footprint with sustained connection intervals")
        elif attack_type == 'UNKNOWN':
            indicators.append(f"Statistical anomaly flagged by Isolation Forest: atypical feature distribution")
            indicators.append(f"Flow behavior significantly deviates from baseline normal network profile")
        else:
            indicators.append("Traffic features conform to standard legitimate network communications")

        return " | ".join(indicators)

    def process_flow(self, raw_flow_data, persist=True):
        """
        Main pipeline function:
        1. Validate & Parse 11 Features
        2. Feature Compatibility Adapter & Normalization
        3. Run AI Models (Isolation Forest & Random Forest)
        4. Threat Scoring & Forensic Reasoner
        5. Persist to DB with Traffic Source & Session ID
        """
        src_ip = raw_flow_data.get('source_ip', '127.0.0.1')
        dst_ip = raw_flow_data.get('destination_ip', '10.0.0.1')
        proto = str(raw_flow_data.get('protocol', 'TCP'))
        dst_port = int(raw_flow_data.get('destination_port', 80))
        duration = max(1e-5, float(raw_flow_data.get('flow_duration', 0.1)))
        total_size = float(raw_flow_data.get('total_flow_size', 1000.0))
        pkt_count = max(1, int(raw_flow_data.get('packet_count', 1)))
        avg_size = float(raw_flow_data.get('average_packet_size', total_size / pkt_count))
        std_size = float(raw_flow_data.get('std_packet_size', 0.0))
        avg_inter_arr = float(raw_flow_data.get('average_inter_arrival_time', 0.01))
        max_inter_arr = float(raw_flow_data.get('maximum_inter_arrival_time', 0.05))
        
        pps = float(raw_flow_data.get('packets_per_second', pkt_count / duration))
        bps = float(raw_flow_data.get('bytes_per_second', total_size / duration))

        traffic_source = raw_flow_data.get('traffic_source', 'live')
        session_id = raw_flow_data.get('session_id', '')

        flow_record = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'protocol': proto,
            'destination_port': dst_port,
            'flow_duration': round(duration, 4),
            'total_flow_size': round(total_size, 2),
            'average_packet_size': round(avg_size, 2),
            'std_packet_size': round(std_size, 2),
            'packet_count': int(pkt_count),
            'average_inter_arrival_time': round(avg_inter_arr, 5),
            'maximum_inter_arrival_time': round(max_inter_arr, 5),
            'packets_per_second': round(pps, 2),
            'bytes_per_second': round(bps, 2),
            'traffic_source': traffic_source,
            'session_id': session_id
        }

        # AI Prediction
        attack_type = 'NORMAL'
        confidence = 0.95
        prediction = 'NORMAL'

        if self.classifier_model and self.preprocessor:
            try:
                df_input = FeatureCompatibilityAdapter.adapt_to_model_features(flow_record)
                X_scaled = self.preprocessor.preprocess(df_input)
                
                # Anomaly prediction (-1 is anomaly, 1 is inlier/normal)
                anomaly_pred = self.anomaly_model.predict(X_scaled)[0] if self.anomaly_model else 1
                
                # Multi-class Classifier
                clf_pred = self.classifier_model.predict(X_scaled)[0]
                decoded_class = self.preprocessor.decode_labels([clf_pred])[0]
                
                probas = [1.0]
                if hasattr(self.classifier_model, 'predict_proba'):
                    probas = self.classifier_model.predict_proba(X_scaled)[0]
                    confidence = float(np.max(probas))

                decoded_upper = decoded_class.upper().replace(' ', '_')

                # Calibrated Arbitration Logic:
                # 1. If classifier predicted Attack with high confidence (>0.52) OR anomaly detector triggered:
                if decoded_upper != 'NORMAL' and (confidence >= 0.52 or anomaly_pred == -1):
                    attack_type = decoded_upper
                    prediction = 'ATTACK'
                # 2. If anomaly detector triggered but classifier said Normal -> UNKNOWN Anomaly
                elif anomaly_pred == -1 and decoded_upper == 'NORMAL':
                    attack_type = 'UNKNOWN'
                    prediction = 'ATTACK'
                # 3. Otherwise, legitimately Normal
                else:
                    attack_type = 'NORMAL'
                    prediction = 'NORMAL'

            except Exception as e:
                print(f"Error in model inference: {e}")
                attack_type = 'NORMAL'
                prediction = 'NORMAL'
        else:
            # Baseline heuristics if models not loaded
            if pps > 2500 or (dst_port in [80, 443] and total_size > 500000 and pkt_count > 500):
                attack_type = 'DDOS'
                prediction = 'ATTACK'
            elif pkt_count <= 4 and dst_port not in [80, 443, 53, 22] and duration < 0.05:
                attack_type = 'PORT_SCAN'
                prediction = 'ATTACK'
            elif dst_port in [22, 21, 3389] and pkt_count > 40:
                attack_type = 'BRUTE_FORCE'
                prediction = 'ATTACK'

        threat_score, severity = self.calculate_threat_metrics(attack_type, confidence)
        indicators = self.generate_indicators(flow_record, attack_type, threat_score)

        result = {
            'flow': flow_record,
            'prediction': prediction,
            'attack_type': attack_type,
            'confidence': confidence,
            'threat_score': threat_score,
            'severity': severity,
            'indicators': indicators,
            'traffic_source': traffic_source,
            'session_id': session_id
        }

        if persist:
            # 1. Save Network Flow
            flow_id = NetworkFlow.create(flow_record)
            result['flow_id'] = flow_id
            
            # 2. Save Detection
            det_id = Detection.create(
                flow_id=flow_id,
                prediction=prediction,
                attack_type=attack_type,
                confidence=confidence,
                threat_score=threat_score,
                severity=severity,
                indicators=indicators,
                traffic_source=traffic_source,
                session_id=session_id
            )
            result['detection_id'] = det_id

            # 3. Create Alert ONLY for confirmed threat with threat_score >= 40
            if prediction == 'ATTACK' and threat_score >= 40:
                title = f"{attack_type.replace('_', ' ').title()} Threat Detected"
                message = f"Suspicious activity ({attack_type}) flagged from source IP {src_ip} targeting {dst_ip}:{dst_port}. Threat Score: {threat_score}/100."
                alert_id = Alert.create(
                    detection_id=det_id,
                    title=title,
                    message=message,
                    severity=severity,
                    status='NEW'
                )
                result['alert_id'] = alert_id

        return result

# Global singleton pipeline instance
pipeline = AIDetectionPipeline()
