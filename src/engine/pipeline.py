import os
import sys
import time
import numpy as np
import pandas as pd
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from preprocessing import Preprocessor, FLOW_NUMERIC_FEATURES
from database.models import NetworkFlow, Detection, Alert
from .feature_adapter import FeatureCompatibilityAdapter

class AIDetectionPipeline:
    """
    Enterprise-Grade Multi-Tiered AI Network Threat Detection & Decision Engine.
    Combines Supervised Random Forest Classification, Unsupervised Isolation Forest,
    Behavioral Correlation, and Strict Confidence Thresholding to minimize False Positives.
    """
    _instance = None

    # Configurable Detection Thresholds
    ATTACK_CONFIDENCE_THRESHOLD = 0.60
    ANOMALY_THRESHOLD = -0.10
    DDOS_PPS_THRESHOLD = 1500.0
    PORT_SCAN_PROBE_THRESHOLD = 10
    AUTH_BURST_THRESHOLD = 6
    ALERT_DEDUPLICATION_WINDOW = 15.0  # seconds

    def __init__(self):
        self.preprocessor = None
        self.anomaly_model = None
        self.classifier_model = None
        self.recent_alerts = {}  # (src_ip, dst_ip, attack_type) -> last_alert_time
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
                    print(f"AI Detection Pipeline loaded models successfully from: {d}")
                    return True
                except Exception as e:
                    print(f"Error loading models from {d}: {e}")
        print("Warning: Trained AI models not found. Running with baseline heuristic fallback.")
        return False

    def calculate_threat_metrics(self, attack_type, confidence=1.0):
        """
        Threat Scoring Matrix:
        - Normal: 0 (LOW)
        - Unknown / Statistical Anomaly: 50 (MEDIUM)
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
        final_score = min(100, max(30, int(base_score * max(0.6, confidence))))
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
            indicators.append(f"Volumetric flood signature: packet rate {pps:.1f} pkt/s, throughput {bps/1024:.1f} KB/s")
            indicators.append(f"High traffic saturation of {pkt_count} packets within {duration:.2f}s targeting port {port}")
        elif attack_type == 'PORT_SCAN':
            probes = flow_dict.get('context_ports_probed', 0)
            indicators.append(f"Reconnaissance scanning pattern targeting port {port}")
            if probes >= 5:
                indicators.append(f"Source IP scanned {probes} distinct ports in short observation window")
        elif attack_type == 'BRUTE_FORCE':
            auth_attempts = flow_dict.get('context_auth_attempts', 0)
            indicators.append(f"Repetitive authentication pattern against service port {port}")
            if auth_attempts >= 3:
                indicators.append(f"Bursts of {auth_attempts} credential handshake attempts detected on authentication port")
        elif attack_type == 'UNKNOWN':
            indicators.append("Statistical anomaly flagged by Isolation Forest: atypical feature distribution")
            indicators.append("Flow behavior significantly deviates from baseline normal network profile")
        else:
            indicators.append("Legitimate network communication conforming to baseline normal profile")

        return " | ".join(indicators)

    def process_flow(self, raw_flow_data, persist=True):
        """
        Main Multi-Tiered AI Pipeline Execution:
        1. Feature Validation & Structuring
        2. Tier 1: Normal Baseline & Local Traffic Verification
        3. Tier 2: Behavioral Evidence Correlation
        4. Tier 3: ML Model Inference & Arbitration
        5. Threat Scoring & Deduplicated Persistence
        """
        src_ip = str(raw_flow_data.get('source_ip', '127.0.0.1'))
        dst_ip = str(raw_flow_data.get('destination_ip', '10.0.0.1'))
        proto = str(raw_flow_data.get('protocol', 'TCP')).upper()
        dst_port = int(raw_flow_data.get('destination_port', 80))
        duration = max(1e-4, float(raw_flow_data.get('flow_duration', 0.1)))
        total_size = max(0.0, float(raw_flow_data.get('total_flow_size', 0.0)))
        pkt_count = max(1, int(raw_flow_data.get('packet_count', 1)))
        
        pps = float(raw_flow_data.get('packets_per_second', pkt_count / duration))
        bps = float(raw_flow_data.get('bytes_per_second', total_size / duration))
        avg_size = float(raw_flow_data.get('average_packet_size', total_size / pkt_count))
        std_size = float(raw_flow_data.get('std_packet_size', 0.0))
        avg_inter_arr = float(raw_flow_data.get('average_inter_arrival_time', 0.0))
        max_inter_arr = float(raw_flow_data.get('maximum_inter_arrival_time', 0.0))

        traffic_source = raw_flow_data.get('traffic_source', 'live')
        session_id = raw_flow_data.get('session_id', '')

        # Behavioral context metrics
        probes_cnt = int(raw_flow_data.get('context_ports_probed', 0))
        auth_cnt = int(raw_flow_data.get('context_auth_attempts', 0))
        tgt_pps = float(raw_flow_data.get('context_target_pps', pps))

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
            'session_id': session_id,
            'context_ports_probed': probes_cnt,
            'context_auth_attempts': auth_cnt
        }

        # -------------------------------------------------------------
        # TIER 1: Normal Baseline & Background Traffic Protection
        # -------------------------------------------------------------
        is_localhost = (src_ip == '127.0.0.1' and dst_ip == '127.0.0.1')
        is_standard_dns = (proto == 'UDP' and dst_port in [53, 5353] and pkt_count <= 20 and pps < 500)
        is_standard_web = (proto == 'TCP' and dst_port in [80, 443, 8080, 8443] and pps < 1200 and pkt_count < 1000)
        is_standard_ntp = (proto == 'UDP' and dst_port in [123, 67, 68] and pkt_count <= 10)
        
        # -------------------------------------------------------------
        # TIER 2: Behavioral Threat Rules
        # -------------------------------------------------------------
        is_behavioral_ddos = (pps >= self.DDOS_PPS_THRESHOLD or tgt_pps >= 2500.0 or (pkt_count >= 1500 and duration < 1.0))
        is_behavioral_portscan = (probes_cnt >= self.PORT_SCAN_PROBE_THRESHOLD and pkt_count <= 15)
        is_behavioral_bruteforce = (dst_port in [22, 21, 3389, 23, 3306, 5432] and auth_cnt >= self.AUTH_BURST_THRESHOLD)

        # -------------------------------------------------------------
        # TIER 3: Machine Learning Model Inference
        # -------------------------------------------------------------
        attack_type = 'NORMAL'
        confidence = 0.98
        prediction = 'NORMAL'

        if self.classifier_model and self.preprocessor:
            try:
                df_input = FeatureCompatibilityAdapter.adapt_to_model_features(flow_record)
                X_scaled = self.preprocessor.preprocess(df_input)
                
                # Isolation Forest: 1 = inlier (normal), -1 = anomaly
                anomaly_pred = self.anomaly_model.predict(X_scaled)[0] if self.anomaly_model else 1
                
                # Multi-class Classifier
                clf_pred = self.classifier_model.predict(X_scaled)[0]
                decoded_class = self.preprocessor.decode_labels([clf_pred])[0].upper().replace(' ', '_')
                
                probas = self.classifier_model.predict_proba(X_scaled)[0]
                max_prob = float(np.max(probas))
                classes = [c.upper().replace(' ', '_') for c in self.preprocessor.decode_labels(range(len(probas)))]
                prob_dict = dict(zip(classes, probas))
                
                prob_normal = float(prob_dict.get('NORMAL', 0.0))
                prob_brute = float(prob_dict.get('BRUTE_FORCE', 0.0))
                prob_ddos = float(prob_dict.get('DDOS', 0.0))
                prob_scan = float(prob_dict.get('PORT_SCAN', 0.0))

                # --- MULTI-TIERED DECISION ARBITRATION ---
                # A. Explicit Behavioral Triggers (Highest Priority)
                if is_behavioral_ddos:
                    attack_type = 'DDOS'
                    confidence = max(0.90, prob_ddos)
                    prediction = 'ATTACK'
                elif is_behavioral_portscan:
                    attack_type = 'PORT_SCAN'
                    confidence = max(0.85, prob_scan)
                    prediction = 'ATTACK'
                elif is_behavioral_bruteforce:
                    attack_type = 'BRUTE_FORCE'
                    confidence = max(0.85, prob_brute)
                    prediction = 'ATTACK'

                # B. Normal Baseline Dominance
                elif is_localhost or is_standard_dns or is_standard_web or is_standard_ntp:
                    # Legitimate background service traffic
                    attack_type = 'NORMAL'
                    confidence = max(0.95, prob_normal)
                    prediction = 'NORMAL'

                # C. High-Confidence ML Classification
                elif decoded_class != 'NORMAL' and max_prob >= self.ATTACK_CONFIDENCE_THRESHOLD:
                    # Require corroborating evidence or high probability
                    if decoded_class == 'PORT_SCAN' and (probes_cnt >= 3 or dst_port not in [80, 443, 53, 22]):
                        attack_type = 'PORT_SCAN'
                        confidence = max_prob
                        prediction = 'ATTACK'
                    elif decoded_class == 'BRUTE_FORCE' and (dst_port in [22, 21, 3389, 23, 3306, 5432] or auth_cnt >= 2):
                        attack_type = 'BRUTE_FORCE'
                        confidence = max_prob
                        prediction = 'ATTACK'
                    elif decoded_class == 'DDOS' and pps >= 500.0:
                        attack_type = 'DDOS'
                        confidence = max_prob
                        prediction = 'ATTACK'
                    else:
                        attack_type = 'NORMAL'
                        confidence = prob_normal
                        prediction = 'NORMAL'

                # D. Unsupervised Anomaly Detection
                elif anomaly_pred == -1 and prob_normal < 0.40 and not (is_standard_web or is_standard_dns):
                    attack_type = 'UNKNOWN'
                    confidence = 0.70
                    prediction = 'ATTACK'

                else:
                    # Standard Normal flow
                    attack_type = 'NORMAL'
                    confidence = max(0.90, prob_normal)
                    prediction = 'NORMAL'

            except Exception as e:
                print(f"Error during AI model inference: {e}")
                attack_type = 'NORMAL'
                prediction = 'NORMAL'
        else:
            # Baseline fallback heuristics
            if is_behavioral_ddos:
                attack_type = 'DDOS'
                prediction = 'ATTACK'
            elif is_behavioral_portscan:
                attack_type = 'PORT_SCAN'
                prediction = 'ATTACK'
            elif is_behavioral_bruteforce:
                attack_type = 'BRUTE_FORCE'
                prediction = 'ATTACK'
            else:
                attack_type = 'NORMAL'
                prediction = 'NORMAL'

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
            # 1. Save EVERY flow to network_flows table (Complete Traffic Telemetry)
            flow_id = NetworkFlow.create(flow_record)
            result['flow_id'] = flow_id
            
            # 2. Save to detections ONLY if confirmed/suspected security incident
            if prediction == 'ATTACK' and threat_score >= 30:
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

                # 3. Create Alert if Threat Score >= 50 with Deduplication
                if threat_score >= 50:
                    alert_key = (src_ip, dst_ip, attack_type)
                    now = time.time()
                    last_alert_time = self.recent_alerts.get(alert_key, 0)
                    
                    if (now - last_alert_time) >= self.ALERT_DEDUPLICATION_WINDOW:
                        self.recent_alerts[alert_key] = now
                        title = f"{attack_type.replace('_', ' ').title()} Threat Detected"
                        message = f"Suspicious activity ({attack_type}) flagged from {src_ip} targeting {dst_ip}:{dst_port}. Threat Score: {threat_score}/100."
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
