import os
import sys
import time
import unittest
import numpy as np
import pandas as pd
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from engine.flow_collector import FlowTable, FlowRecord, BehavioralTracker
from engine.pipeline import pipeline
from engine.feature_adapter import FeatureCompatibilityAdapter
from preprocessing import FLOW_NUMERIC_FEATURES
from database.models import NetworkFlow, Detection, Alert


def fake_sniff(*args, **kwargs):
    timeout = kwargs.get('timeout', 0.2)
    time.sleep(min(0.05, timeout))


class TestComprehensiveDetectionPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pipeline.load_models()

    def setUp(self):
        self.flow_table = FlowTable(flow_timeout=10.0, active_timeout=2.0)

    # 1. Feature Extraction from raw packets to 11 standard flow features
    def test_01_feature_extraction(self):
        record = FlowRecord('10.0.0.5', '10.0.0.1', 'TCP', 50000, 80, start_time=100.0)
        record.add_packet('10.0.0.5', '10.0.0.1', 50000, 80, 100, pkt_time=100.0, tcp_flags=0x02)
        record.add_packet('10.0.0.5', '10.0.0.1', 50000, 80, 200, pkt_time=100.5, tcp_flags=0x18)
        record.add_packet('10.0.0.1', '10.0.0.5', 80, 50000, 300, pkt_time=101.0, tcp_flags=0x18)

        features = record.calculate_features(current_time=101.0)
        self.assertEqual(features['packet_count'], 3)
        self.assertEqual(features['total_flow_size'], 600.0)
        self.assertAlmostEqual(features['average_packet_size'], 200.0, places=1)
        self.assertAlmostEqual(features['flow_duration'], 1.0, places=2)
        self.assertEqual(features['forward_packets'], 2)
        self.assertEqual(features['reverse_packets'], 1)
        self.assertGreater(features['packets_per_second'], 0)
        self.assertGreater(features['bytes_per_second'], 0)

    # 2. 11-to-9 feature adaptation with FeatureCompatibilityAdapter
    def test_02_feature_adapter_schema(self):
        flow_dict = {
            'flow_duration': 2.5,
            'packet_count': 50,
            'total_flow_size': 15000.0,
            'packets_per_second': 20.0,
            'bytes_per_second': 6000.0,
            'average_packet_size': 300.0,
            'std_packet_size': 50.0,
            'average_inter_arrival_time': 0.05,
            'maximum_inter_arrival_time': 0.12
        }
        df = FeatureCompatibilityAdapter.adapt_to_model_features(flow_dict)
        self.assertEqual(list(df.columns), FLOW_NUMERIC_FEATURES)
        self.assertEqual(df.shape, (1, 9))
        self.assertEqual(df['packet_count'].iloc[0], 50)

    # 3. Invalid and incomplete packet handling (NaN, Inf, 0 duration)
    def test_03_invalid_incomplete_packet_handling(self):
        flow_edge = {
            'flow_duration': 0.0,
            'packet_count': 1,
            'total_flow_size': 0.0,
            'packets_per_second': float('inf'),
            'bytes_per_second': float('nan')
        }
        df = FeatureCompatibilityAdapter.adapt_to_model_features(flow_edge)
        scaled = pipeline.preprocessor.preprocess(df)
        self.assertFalse(np.isnan(scaled).any())
        self.assertFalse(np.isinf(scaled).any())
        self.assertEqual(scaled.shape, (1, 9))

    # 4. Flow aggregation, canonical key, and expiration
    def test_04_flow_aggregation_canonical_key(self):
        t0 = 1000.0
        # Forward packet
        self.flow_table.process_packet('192.168.1.10', '192.168.1.20', 'TCP', 80, 45000, 60, pkt_time=t0, tcp_flags=0x02)
        # Reverse packet
        self.flow_table.process_packet('192.168.1.20', '192.168.1.10', 'TCP', 45000, 80, 60, pkt_time=t0 + 0.1, tcp_flags=0x12)

        self.assertEqual(self.flow_table.get_active_flow_count(), 1)
        # Not expired before flow_timeout (10s)
        expired_early = self.flow_table.get_expired_flows(current_time=t0 + 5.0)
        self.assertEqual(len(expired_early), 0)
        # Expired after flow_timeout
        expired_late = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        self.assertEqual(len(expired_late), 1)
        self.assertEqual(expired_late[0]['packet_count'], 2)

    # 5. Random Forest input validation and class mapping
    def test_05_random_forest_classification(self):
        df_normal = pd.DataFrame([{
            'total_flow_size': 5000.0, 'average_packet_size': 250.0, 'std_packet_size': 50.0,
            'packet_count': 20, 'flow_duration': 2.0, 'average_inter_arrival_time': 0.1,
            'maximum_inter_arrival_time': 0.2, 'packets_per_second': 10.0, 'bytes_per_second': 2500.0
        }])
        X_scaled = pipeline.preprocessor.preprocess(df_normal)
        pred = pipeline.classifier_model.predict(X_scaled)[0]
        decoded = pipeline.preprocessor.decode_labels([pred])[0]
        self.assertIn(decoded, ['Normal', 'DDoS', 'Port Scan', 'Brute Force'])
        probas = pipeline.classifier_model.predict_proba(X_scaled)[0]
        self.assertEqual(len(probas), 4)
        self.assertAlmostEqual(sum(probas), 1.0, places=4)

    # 6. Isolation Forest anomaly interpretation
    def test_06_isolation_forest_anomaly_detection(self):
        # Atypical extreme flow: 10,000 pkts, 0.001s duration, huge IAT jitter
        df_anomaly = pd.DataFrame([{
            'total_flow_size': 9999999.0, 'average_packet_size': 50000.0, 'std_packet_size': 99999.0,
            'packet_count': 10000, 'flow_duration': 0.001, 'average_inter_arrival_time': 999.0,
            'maximum_inter_arrival_time': 9999.0, 'packets_per_second': 9999999.0, 'bytes_per_second': 99999999.0
        }])
        X_scaled = pipeline.preprocessor.preprocess(df_anomaly)
        anom_pred = pipeline.anomaly_model.predict(X_scaled)[0]
        anom_score = pipeline.anomaly_model.decision_function(X_scaled)[0]
        self.assertEqual(anom_pred, -1, "Extreme outlier was not flagged by Isolation Forest!")
        self.assertLess(anom_score, 0.0, "Anomaly score for outlier should be negative!")

    # 7. Unknown anomalies preserved and generating alerts (Fix F1 & F2)
    def test_07_unknown_anomalies_preserved_and_alerted(self):
        # Synthetic atypical flow that triggers Isolation Forest outlier without high-rate DDoS flood
        flow_outlier = {
            'source_ip': '192.168.100.55', 'destination_ip': '192.168.100.1', 'protocol': 'TCP',
            'source_port': 54321, 'destination_port': 9999, 'flow_duration': 60.0,
            'total_flow_size': 50000.0, 'average_packet_size': 10000.0, 'std_packet_size': 5000.0,
            'packet_count': 5, 'average_inter_arrival_time': 15.0, 'maximum_inter_arrival_time': 30.0,
            'packets_per_second': 0.083, 'bytes_per_second': 833.33
        }
        res = pipeline.process_flow(flow_outlier, persist=False)
        self.assertEqual(res['anomaly_prediction'], -1)
        self.assertEqual(res['final_label'], 'UNKNOWN')
        self.assertEqual(res['prediction'], 'ATTACK')
        self.assertGreaterEqual(res['threat_score'], 50, "Unknown anomalies must have threat_score >= 50 for alerting!")
        self.assertEqual(res['severity'], 'MEDIUM')
        self.assertIn("Isolation Forest", res['indicators'])

    # 8. High-rate volumetric DDoS detection (per-flow & target aggregated)
    def test_08_ddos_detection_and_attribution(self):
        t0 = time.time()
        for i in range(600):
            t = t0 + (i * 0.0003)  # > 3000 pps
            self.flow_table.process_packet('10.0.0.50', '10.0.0.1', 'TCP', 80, 54321, 60, pkt_time=t, tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        self.assertGreaterEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertEqual(res['final_label'], 'DDOS')
        self.assertEqual(res['prediction'], 'ATTACK')
        self.assertGreaterEqual(res['threat_score'], 80)
        self.assertEqual(res['severity'], 'CRITICAL')

    # 9. Port scanning detection and scanner/target IP attribution
    def test_09_port_scan_detection_and_attribution(self):
        t0 = time.time()
        scanner = '192.168.100.10'
        target = '192.168.100.20'
        for p in range(1, 20):
            self.flow_table.process_packet(scanner, target, 'TCP', p, 50000 + p, 60, pkt_time=t0 + (p * 0.05), tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        scan_results = [pipeline.process_flow(f, persist=False) for f in expired]
        detected = [r for r in scan_results if r['final_label'] == 'PORT_SCAN']
        self.assertGreater(len(detected), 0, "Port scan was not detected!")
        # Verify scanner and target IP attribution
        self.assertEqual(detected[0]['flow']['source_ip'], scanner)
        self.assertEqual(detected[0]['flow']['destination_ip'], target)
        self.assertEqual(detected[0]['severity'], 'HIGH')

    # 10. Port scanning early detection without 10s delay (Fix F3)
    def test_10_port_scan_early_detection_criterion_c(self):
        t0 = time.time()
        scanner = '192.168.1.15'
        target = '192.168.1.25'
        # 12 probes within 0.6 seconds
        for p in range(1, 13):
            self.flow_table.process_packet(scanner, target, 'TCP', p, 60000 + p, 60, pkt_time=t0 + (p * 0.05), tcp_flags=0x02)

        # Check early analysis at t0 + 1.2s (long before the 10s inactivity timeout)
        early_flows = self.flow_table.get_expired_flows(current_time=t0 + 1.2)
        self.assertGreater(len(early_flows), 0, "Criterion C failed to trigger early analysis during active port scan!")
        self.assertEqual(early_flows[0]['rate_status'], 'ACTIVE_SNAPSHOT')
        res = pipeline.process_flow(early_flows[0], persist=False)
        self.assertEqual(res['final_label'], 'PORT_SCAN')

    # 11. Brute force connection bursts on authentication ports
    def test_11_brute_force_detection(self):
        t0 = time.time()
        for i in range(10):
            self.flow_table.process_packet('10.10.10.10', '10.10.10.20', 'TCP', 22, 40000 + i, 120, pkt_time=t0 + (i * 0.3), tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        bf_found = False
        for f in expired:
            r = pipeline.process_flow(f, persist=False)
            if r['final_label'] == 'BRUTE_FORCE':
                bf_found = True
                self.assertGreaterEqual(r['threat_score'], 70)
                break
        self.assertTrue(bf_found, "Brute force attack was not detected!")

    # 12. Normal web traffic (HTTPS/DNS/NTP) without false alarms
    def test_12_normal_traffic_zero_false_alarms(self):
        t0 = time.time()
        for i in range(50):
            t = t0 + (i * 0.2)
            self.flow_table.process_packet('10.0.2.15', '142.250.190.46', 'TCP', 443, 55555, 1200, pkt_time=t, tcp_flags=0x18)
            self.flow_table.process_packet('142.250.190.46', '10.0.2.15', 'TCP', 55555, 443, 800, pkt_time=t + 0.02, tcp_flags=0x18)

        expired = self.flow_table.get_expired_flows(current_time=t0 + 25.0)
        self.assertEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertEqual(res['final_label'], 'NORMAL')
        self.assertEqual(res['prediction'], 'NORMAL')
        self.assertEqual(res['threat_score'], 0)

    # 13. Multi-port scan covering port 80/443 not suppressed (Fix F4)
    def test_13_port_scan_including_web_ports_detected(self):
        t0 = time.time()
        scanner = '172.16.0.5'
        target = '172.16.0.10'
        # Scan 16 ports including port 80 and 443
        ports = list(range(70, 85)) + [443]
        for p in ports:
            self.flow_table.process_packet(scanner, target, 'TCP', p, 52000, 60, pkt_time=t0 + (p * 0.02), tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        port_80_flow = next((f for f in expired if f['destination_port'] == 80), None)
        self.assertIsNotNone(port_80_flow)
        res = pipeline.process_flow(port_80_flow, persist=False)
        self.assertEqual(res['final_label'], 'PORT_SCAN', "Port 80 probe was suppressed despite broad scan sweep!")

    # 14. Alert deduplication & memory pruning (Fix F5)
    def test_14_alert_deduplication_and_pruning(self):
        pipeline.recent_alerts.clear()
        flow_attack = {
            'source_ip': '1.2.3.4', 'destination_ip': '5.6.7.8', 'protocol': 'TCP',
            'source_port': 1111, 'destination_port': 80, 'flow_duration': 0.05,
            'total_flow_size': 50000.0, 'packet_count': 600, 'packets_per_second': 3000.0,
            'bytes_per_second': 250000.0
        }
        # First evaluation should generate alert
        res1 = pipeline.process_flow(flow_attack, persist=True)
        self.assertIn('alert_id', res1)

        # Immediate second evaluation should be deduplicated (no new alert_id)
        res2 = pipeline.process_flow(flow_attack, persist=True)
        self.assertNotIn('alert_id', res2)

        # Pre-fill dictionary with 600 dummy old entries to trigger pruning
        now = time.time()
        for i in range(600):
            pipeline.recent_alerts[(f'10.0.{i // 255}.{i % 255}', '10.0.0.1', 'DDOS')] = now - 100.0

        # Next alert creation triggers pruning
        flow_attack_new = {
            'source_ip': '9.9.9.9', 'destination_ip': '5.6.7.8', 'protocol': 'TCP',
            'source_port': 2222, 'destination_port': 80, 'flow_duration': 0.05,
            'total_flow_size': 50000.0, 'packet_count': 600, 'packets_per_second': 3000.0,
            'bytes_per_second': 250000.0
        }
        res3 = pipeline.process_flow(flow_attack_new, persist=True)
        self.assertIn('alert_id', res3)
        self.assertLess(len(pipeline.recent_alerts), 500, "recent_alerts was not pruned to bounded size!")

    # 15. Bidirectional VM-to-VM traffic aggregation and monitoring host processing
    def test_15_vm_to_vm_traffic_aggregation(self):
        vm1 = '192.168.100.10'  # Alpine VM
        vm2 = '192.168.100.20'  # Windows VM
        t0 = time.time()
        for i in range(25):
            t = t0 + (i * 0.02)
            self.flow_table.process_packet(vm1, vm2, 'TCP', 80, 49200, 64, pkt_time=t, tcp_flags=0x18)
            self.flow_table.process_packet(vm2, vm1, 'TCP', 49200, 80, 1400, pkt_time=t + 0.005, tcp_flags=0x18)

        self.assertEqual(self.flow_table.get_active_flow_count(), 1)
        expired = self.flow_table.get_expired_flows(current_time=t0 + 15.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]['forward_packets'], 25)
        self.assertEqual(expired[0]['reverse_packets'], 25)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertIn(res['prediction'], ['NORMAL', 'ATTACK'])


if __name__ == '__main__':
    unittest.main()
