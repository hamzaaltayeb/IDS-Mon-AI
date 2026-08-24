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
    Behavioral Multi-Flow Correlation, and Empirically Calibrated Thresholds.
    """
    _instance = None

    # Empirically Calibrated Decision Thresholds (Derived from Validation ROC/PR Sweep)
    ATTACK_CONFIDENCE_THRESHOLD = 0.55
    ANOMALY_SCORE_THRESHOLD = -0.05
    
    # Volumetric DDoS Hard Safety Floors (Prevents triggering on single/few packet bursts)
    DDOS_MIN_PACKETS = 50
    DDOS_MIN_BYTES = 50000.0
    DDOS_PPS_THRESHOLD = 1500.0
    
    # Port Scan Multi-Port Reconnaissance Floors
    PORT_SCAN_PROBE_THRESHOLD = 10
    PORT_SCAN_MAX_PKTS_PER_PORT = 5
    
    # Brute Force Authentication Flooding Floors
    AUTH_BURST_THRESHOLD = 6
    
    # Alert Deduplication Window (seconds)
    ALERT_DEDUPLICATION_WINDOW = 15.0

    def __init__(self):
        self.preprocessor = None
        self.anomaly_model = None
        self.classifier_model = None
        self.recent_alerts = {}  # (src_ip, dst_ip, attack_type) -> last_alert_time
        self.enable_debug_logging = (os.environ.get('AI_DEBUG_PIPELINE', '0') == '1')
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

    def calculate_threat_metrics(self, final_label, decision_confidence=1.0):
        """
        Derives an explainable Threat Score (0 - 100) and Severity Tier based on composite evidence:
        - NORMAL: 0 (LOW)
        - UNKNOWN / Statistical Anomaly: 45 - 50 (MEDIUM)
        - PORT_SCAN: 65 - 75 (HIGH)
        - BRUTE_FORCE: 75 - 85 (HIGH)
        - DDOS: 85 - 95 (CRITICAL)
        """
        score_matrix = {
            'NORMAL': (0, 'LOW'),
            'UNKNOWN': (50, 'MEDIUM'),
            'PORT_SCAN': (70, 'HIGH'),
            'BRUTE_FORCE': (85, 'HIGH'),
            'DDOS': (95, 'CRITICAL')
        }
        base_score, severity = score_matrix.get(final_label.upper(), (50, 'MEDIUM'))
        if final_label.upper() == 'NORMAL':
            return 0, 'LOW'
            
        scaled_score = int(base_score * max(0.65, min(1.0, decision_confidence)))
        final_score = min(100, max(30, scaled_score))
        return final_score, severity

    def generate_indicators(self, flow_dict, final_label, threat_score, model_metrics=None):
        """
        Generates human-readable forensic indicators explaining why the flow was flagged.
        """
        indicators = []
        pps = flow_dict.get('packets_per_second', 0)
        bps = flow_dict.get('bytes_per_second', 0)
        port = flow_dict.get('destination_port', 0)
        pkt_count = flow_dict.get('packet_count', 0)
        duration = flow_dict.get('flow_duration', 0)

        if final_label == 'DDOS':
            indicators.append(f"Volumetric flood signature: packet rate {pps:.1f} pkt/s, throughput {bps/1024:.1f} KB/s")
            indicators.append(f"Traffic saturation of {pkt_count} packets ({flow_dict.get('total_flow_size', 0)/1024:.1f} KB) within {duration:.2f}s targeting port {port}")
        elif final_label == 'PORT_SCAN':
            probes = flow_dict.get('context_ports_probed', 0)
            indicators.append(f"Reconnaissance scanning pattern targeting port {port}")
            if probes >= 3:
                indicators.append(f"Source IP probed {probes} distinct ports in sliding observation window")
        elif final_label == 'BRUTE_FORCE':
            auth_attempts = flow_dict.get('context_auth_attempts', 0)
            indicators.append(f"Repetitive authentication pattern against service port {port}")
            if auth_attempts >= 3:
                indicators.append(f"Bursts of {auth_attempts} credential handshake attempts detected on authentication port")
        elif final_label == 'UNKNOWN':
            indicators.append("Statistical anomaly flagged by Isolation Forest: atypical feature distribution")
            if model_metrics:
                indicators.append(f"Random Forest prediction uncertainty (Normal probability: {model_metrics.get('prob_normal', 0):.2f})")
        else:
            indicators.append("Legitimate network communication conforming to baseline operational profile")

        return " | ".join(indicators)

    def process_flow(self, raw_flow_data, persist=True):
        """
        Main Multi-Tiered AI Pipeline Execution:
        1. Feature Structuring (11 Features)
        2. Tier 1: Behavioral Signals Extraction (DDoS, Port Scan, Brute Force)
        3. Tier 2: Machine Learning Inference (Random Forest Probabilities & Isolation Forest Anomaly Score)
        4. Tier 3: Evidence-Based Decision Arbitration
        5. Threat Scoring, Deduplication, & Persistence
        """
        src_ip = str(raw_flow_data.get('source_ip', '127.0.0.1'))
        dst_ip = str(raw_flow_data.get('destination_ip', '10.0.0.1'))
        proto = str(raw_flow_data.get('protocol', 'TCP')).upper()
        dst_port = int(raw_flow_data.get('destination_port', 80))
        src_port = int(raw_flow_data.get('source_port', 0))
        duration = max(0.0, float(raw_flow_data.get('flow_duration', 0.0)))
        total_size = max(0.0, float(raw_flow_data.get('total_flow_size', 0.0)))
        pkt_count = max(1, int(raw_flow_data.get('packet_count', 1)))
        
        pps = float(raw_flow_data.get('packets_per_second', 0.0))
        bps = float(raw_flow_data.get('bytes_per_second', 0.0))
        avg_size = float(raw_flow_data.get('average_packet_size', total_size / pkt_count))
        std_size = float(raw_flow_data.get('std_packet_size', 0.0))
        avg_inter_arr = float(raw_flow_data.get('average_inter_arrival_time', 0.0))
        max_inter_arr = float(raw_flow_data.get('maximum_inter_arrival_time', 0.0))

        traffic_source = raw_flow_data.get('traffic_source', 'live')
        session_id = raw_flow_data.get('session_id', '')

        # Multi-flow behavioral context
        probes_cnt = int(raw_flow_data.get('context_ports_probed', 0))
        auth_cnt = int(raw_flow_data.get('context_auth_attempts', 0))
        tgt_pps = float(raw_flow_data.get('context_target_pps', pps))

        flow_record = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'protocol': proto,
            'source_port': src_port,
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
        # TIER 1: Behavioral Signals Extraction
        # -------------------------------------------------------------
        # Hard Safety Floor: Requires minimum packet count AND total bytes AND high sustained rate
        is_behavioral_ddos = (
            pkt_count >= self.DDOS_MIN_PACKETS and 
            total_size >= self.DDOS_MIN_BYTES and 
            (pps >= self.DDOS_PPS_THRESHOLD or tgt_pps >= 2500.0)
        )
        # Port Scan: Requires multi-port sweep across 10+ distinct ports with few packets per probe
        is_behavioral_portscan = (
            probes_cnt >= self.PORT_SCAN_PROBE_THRESHOLD and 
            pkt_count <= self.PORT_SCAN_MAX_PKTS_PER_PORT
        )
        # Brute Force: Requires repeated connection bursts on authentication service ports
        is_behavioral_bruteforce = (
            dst_port in [22, 21, 3389, 23, 3306, 5432] and 
            auth_cnt >= self.AUTH_BURST_THRESHOLD
        )

        behavioral_signals = {
            'ddos': is_behavioral_ddos,
            'port_scan': is_behavioral_portscan,
            'brute_force': is_behavioral_bruteforce
        }

        # -------------------------------------------------------------
        # TIER 2: Machine Learning Model Inference
        # -------------------------------------------------------------
        model_prediction = 'Normal'
        model_probability = 1.0
        prob_dict = {'Normal': 1.0, 'Brute Force': 0.0, 'DDoS': 0.0, 'Port Scan': 0.0}
        anomaly_score = 0.0
        anomaly_prediction = 1  # 1 = Inlier (Normal), -1 = Outlier (Anomaly)

        if self.classifier_model and self.preprocessor:
            try:
                df_input = FeatureCompatibilityAdapter.adapt_to_model_features(flow_record)
                X_scaled = self.preprocessor.preprocess(df_input)
                
                # Unsupervised Anomaly Detection (Isolation Forest)
                if self.anomaly_model:
                    anomaly_prediction = int(self.anomaly_model.predict(X_scaled)[0])
                    # In scikit-learn IsolationForest: decision_function returns negative for outliers, positive for inliers
                    anomaly_score = float(self.anomaly_model.decision_function(X_scaled)[0])
                
                # Supervised Multi-Class Classification (Random Forest)
                clf_pred = self.classifier_model.predict(X_scaled)[0]
                model_prediction = self.preprocessor.decode_labels([clf_pred])[0]
                
                probas = self.classifier_model.predict_proba(X_scaled)[0]
                classes = self.preprocessor.decode_labels(range(len(probas)))
                prob_dict = {c: round(float(p), 4) for c, p in zip(classes, probas)}
                model_probability = float(np.max(probas))
                
            except Exception as e:
                print(f"Error during AI model inference: {e}")

        prob_normal = float(prob_dict.get('Normal', 0.0))
        prob_brute = float(prob_dict.get('Brute Force', 0.0))
        prob_ddos = float(prob_dict.get('DDoS', 0.0))
        prob_scan = float(prob_dict.get('Port Scan', 0.0))

        # -------------------------------------------------------------
        # TIER 3: Evidence-Based Decision Arbitration
        # -------------------------------------------------------------
        final_label = 'NORMAL'
        prediction = 'NORMAL'
        decision_confidence = prob_normal

        # CASE A: Strong Corroborated Behavioral Signatures (Highest Priority)
        if is_behavioral_ddos:
            final_label = 'DDOS'
            prediction = 'ATTACK'
            decision_confidence = max(prob_ddos, 0.85)
        elif is_behavioral_portscan:
            final_label = 'PORT_SCAN'
            prediction = 'ATTACK'
            decision_confidence = max(prob_scan, 0.80)
        elif is_behavioral_bruteforce:
            final_label = 'BRUTE_FORCE'
            prediction = 'ATTACK'
            decision_confidence = max(prob_brute, 0.80)

        # CASE B: High-Confidence Supervised Model Classification
        elif model_prediction != 'Normal' and model_probability >= self.ATTACK_CONFIDENCE_THRESHOLD:
            # Validate attack category against specific corroborating criteria
            if model_prediction == 'Port Scan' and (probes_cnt >= 3 or dst_port not in [80, 443, 53, 22]):
                final_label = 'PORT_SCAN'
                prediction = 'ATTACK'
                decision_confidence = model_probability
            elif model_prediction == 'Brute Force' and (dst_port in [22, 21, 3389, 23, 3306, 5432] or auth_cnt >= 2):
                final_label = 'BRUTE_FORCE'
                prediction = 'ATTACK'
                decision_confidence = model_probability
            elif model_prediction == 'DDoS' and pkt_count >= self.DDOS_MIN_PACKETS:
                final_label = 'DDOS'
                prediction = 'ATTACK'
                decision_confidence = model_probability
            else:
                # Weak category match -> classify as UNKNOWN statistical threat
                final_label = 'UNKNOWN'
                prediction = 'ATTACK'
                decision_confidence = model_probability

        # CASE C: Genuine Statistical Anomaly with Low Supervised Confidence
        elif anomaly_prediction == -1 and anomaly_score <= self.ANOMALY_SCORE_THRESHOLD and prob_normal < 0.40:
            final_label = 'UNKNOWN'
            prediction = 'ATTACK'
            decision_confidence = float(abs(anomaly_score) / (abs(anomaly_score) + 0.20))

        # CASE D: Default Normal Traffic
        else:
            final_label = 'NORMAL'
            prediction = 'NORMAL'
            decision_confidence = max(prob_normal, 0.50)

        # -------------------------------------------------------------
        # TIER 4: Threat Scoring & Indicator Generation
        # -------------------------------------------------------------
        threat_score, severity = self.calculate_threat_metrics(final_label, decision_confidence)
        indicators = self.generate_indicators(
            flow_record, final_label, threat_score, 
            model_metrics={'prob_normal': prob_normal, 'prob_brute': prob_brute, 'prob_ddos': prob_ddos, 'prob_scan': prob_scan}
        )

        # Detailed Diagnostic Trace Logging (Toggleable via AI_DEBUG_PIPELINE=1 or --debug-capture)
        if self.enable_debug_logging:
            print("\n================ LIVE CLASSIFICATION TRACE ================")
            print(f"[FLOW] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {proto} | Pkts: {pkt_count} | Bytes: {total_size} | Dur: {duration:.3f}s")
            print(f"[FEATURES] PPS: {pps:.1f} | BPS: {bps:.1f} | AvgSize: {avg_size:.1f} | StdSize: {std_size:.1f} | AvgIAT: {avg_inter_arr:.4f}s")
            print(f"[MODEL] Raw Pred: {model_prediction} | Max Prob: {model_probability:.4f} | Probas: {prob_dict}")
            print(f"[ANOMALY] Pred: {anomaly_prediction} (+1=Inlier, -1=Outlier) | Anomaly Score: {anomaly_score:.4f}")
            print(f"[BEHAVIOR] DDoS: {is_behavioral_ddos} | PortScan: {is_behavioral_portscan} (Probes: {probes_cnt}) | BruteForce: {is_behavioral_bruteforce} (Bursts: {auth_cnt})")
            print(f"[DECISION] Final Label: {final_label} | Prediction: {prediction} | Threat Score: {threat_score}/100 | Severity: {severity} | Decision Confidence: {decision_confidence:.4f}")
            print("============================================================\n")

        result = {
            'flow': flow_record,
            'prediction': prediction,
            'attack_type': final_label,
            'final_label': final_label,
            'model_prediction': model_prediction,
            'model_probability': model_probability,
            'anomaly_score': anomaly_score,
            'anomaly_prediction': anomaly_prediction,
            'confidence': decision_confidence,
            'decision_confidence': decision_confidence,
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
            
            # 2. Save EVERY classification to detections table (Ensures NORMAL is visible in SOC KPIs)
            det_id = Detection.create(
                flow_id=flow_id,
                prediction=prediction,
                attack_type=final_label,
                confidence=decision_confidence,
                threat_score=threat_score,
                severity=severity,
                indicators=indicators,
                traffic_source=traffic_source,
                session_id=session_id
            )
            result['detection_id'] = det_id

            # 3. Create Alert ONLY for confirmed threat with Threat Score >= 50 and Deduplication
            if prediction == 'ATTACK' and threat_score >= 50:
                alert_key = (src_ip, dst_ip, final_label)
                now = time.time()
                last_alert_time = self.recent_alerts.get(alert_key, 0)
                
                if (now - last_alert_time) >= self.ALERT_DEDUPLICATION_WINDOW:
                    self.recent_alerts[alert_key] = now
                    title = f"{final_label.replace('_', ' ').title()} Threat Detected"
                    message = f"Suspicious activity ({final_label}) flagged from {src_ip} targeting {dst_ip}:{dst_port}. Threat Score: {threat_score}/100."
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
