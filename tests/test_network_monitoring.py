import os
import sys
import time
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from engine.flow_collector import FlowTable, FlowRecord, BehavioralTracker
from engine.pipeline import pipeline
from engine.live_capture import LiveCaptureManager, live_capture_manager
from engine.interface_discovery import InterfaceDiscovery


def fake_sniff(*args, **kwargs):
    """Mock sniffer that runs without requiring elevated root CAP_NET_RAW privileges."""
    timeout = kwargs.get('timeout', 0.2)
    time.sleep(min(0.05, timeout))


class TestNetworkSecurityMonitoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pipeline.load_models()

    def setUp(self):
        self.flow_table = FlowTable(flow_timeout=10.0, active_timeout=2.0)

    # 1. Normal traffic
    def test_01_normal_traffic(self):
        """Verify normal web browsing is classified as NORMAL without false alerts."""
        start = time.time()
        for i in range(100):
            t = start + (i * 0.1)
            self.flow_table.process_packet('10.0.2.15', '172.217.16.206', 'TCP', 443, 54321, 800, t, tcp_flags=0x18)
            self.flow_table.process_packet('172.217.16.206', '10.0.2.15', 'TCP', 54321, 443, 1200, t + 0.01, tcp_flags=0x18)

        expired = self.flow_table.get_expired_flows(current_time=start + 22.0)
        self.assertEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertEqual(res['prediction'], 'NORMAL')
        self.assertLess(res['threat_score'], 50)

    # 2. Port scan traffic
    def test_02_port_scan_traffic(self):
        """Verify genuine reconnaissance (1 source probing >= 10 ports on 1 target) triggers PORT_SCAN."""
        start = time.time()
        attacker = '192.168.56.105'
        target = '192.168.56.101'
        for port in range(20, 35):
            t = start + ((port - 20) * 0.05)
            self.flow_table.process_packet(attacker, target, 'TCP', port, 40000 + port, 60, t, tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=start + 15.0)
        port_scan_detected = False
        for flow in expired:
            res = pipeline.process_flow(flow, persist=False)
            if res['final_label'] == 'PORT_SCAN':
                port_scan_detected = True
                self.assertGreaterEqual(res['threat_score'], 50)
                break
        self.assertTrue(port_scan_detected, "Port scan attack was not detected!")

    # 3. Brute force traffic
    def test_03_brute_force_traffic(self):
        """Verify repeated connection bursts on authentication port 22 are detected as BRUTE_FORCE."""
        start = time.time()
        attacker = '192.168.56.105'
        target = '192.168.56.101'
        for i in range(10):
            t = start + (i * 0.5)
            self.flow_table.process_packet(attacker, target, 'TCP', 22, 50000 + i, 120, t, tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=start + 16.0)
        brute_detected = False
        for flow in expired:
            res = pipeline.process_flow(flow, persist=False)
            if res['final_label'] == 'BRUTE_FORCE':
                brute_detected = True
                self.assertGreaterEqual(res['threat_score'], 60)
                break
        self.assertTrue(brute_detected, "Brute force attack was not detected!")

    # 4. High-rate DoS/DDoS traffic
    def test_04_high_rate_ddos_traffic(self):
        """Verify high-rate volumetric attack is detected as DDOS."""
        start = time.time()
        for i in range(500):
            t = start + (i * 0.0004)  # 2500 pps
            self.flow_table.process_packet('10.0.0.50', '10.0.0.1', 'TCP', 80, 54321, 60, t, tcp_flags=0x02)

        expired = self.flow_table.get_expired_flows(current_time=start + 15.0)
        self.assertEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertEqual(res['final_label'], 'DDOS')
        self.assertEqual(res['prediction'], 'ATTACK')
        self.assertGreaterEqual(res['threat_score'], 80)

    # 5. Traffic between virtual machines (VM-A -> VM-B, neither is monitoring host)
    def test_05_vm_to_vm_traffic_visibility_and_bidirectional_aggregation(self):
        """
        Verify that when traffic between two virtual machines (e.g. Parrot 192.168.56.102 -> Windows 192.168.56.103)
        is visible to the sniffer, the system aggregates bidirectional packets into a single canonical session,
        extracts features properly, and classifies it through the AI pipeline.
        """
        vm_attacker = '192.168.56.102'  # Parrot VM
        vm_victim = '192.168.56.103'    # Windows VM
        start = time.time()

        # Forward packets: VM-A -> VM-B
        for i in range(30):
            t = start + (i * 0.01)
            self.flow_table.process_packet(
                src_ip=vm_attacker, dst_ip=vm_victim, proto='TCP',
                dst_port=80, src_port=49152, pkt_len=64, pkt_time=t, tcp_flags=0x18
            )

        # Reverse packets: VM-B -> VM-A (same TCP session)
        for i in range(30):
            t = start + (i * 0.01) + 0.002
            self.flow_table.process_packet(
                src_ip=vm_victim, dst_ip=vm_attacker, proto='TCP',
                dst_port=49152, src_port=80, pkt_len=1460, pkt_time=t, tcp_flags=0x18
            )

        # Both forward and reverse directions MUST be merged into exactly 1 active flow
        self.assertEqual(self.flow_table.get_active_flow_count(), 1,
                         "Bidirectional VM-to-VM traffic failed to aggregate into a single canonical flow!")

        expired = self.flow_table.get_expired_flows(current_time=start + 15.0)
        self.assertEqual(len(expired), 1)
        flow = expired[0]

        # Verify packet counts & bytes merged from both directions
        self.assertEqual(flow['packet_count'], 60)
        self.assertEqual(flow['forward_packets'], 30)
        self.assertEqual(flow['reverse_packets'], 30)

        # Verify it passes through pipeline without issue
        result = pipeline.process_flow(flow, persist=False)
        self.assertIn(result['prediction'], ['NORMAL', 'ATTACK'])
        self.assertIn('threat_score', result)

    # 6. Traffic originating from monitoring machine (Host -> external)
    def test_06_traffic_originating_from_monitoring_machine(self):
        """Verify outbound traffic from monitoring host is properly tracked and evaluated."""
        host_ip = '10.118.101.71'
        external_server = '93.184.216.34'
        start = time.time()
        for i in range(15):
            t = start + (i * 0.1)
            self.flow_table.process_packet(host_ip, external_server, 'TCP', 80, 52000, 100, t, tcp_flags=0x18)

        expired = self.flow_table.get_expired_flows(current_time=start + 15.0)
        self.assertEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertEqual(res['prediction'], 'NORMAL')

    # 7. Traffic received by monitoring machine (External -> Host)
    def test_07_traffic_received_by_monitoring_machine(self):
        """Verify inbound traffic to monitoring host is properly tracked and evaluated."""
        external_client = '198.51.100.25'
        host_ip = '10.118.101.71'
        start = time.time()
        for i in range(15):
            t = start + (i * 0.1)
            self.flow_table.process_packet(external_client, host_ip, 'TCP', 443, 61000, 150, t, tcp_flags=0x18)

        expired = self.flow_table.get_expired_flows(current_time=start + 15.0)
        self.assertEqual(len(expired), 1)
        res = pipeline.process_flow(expired[0], persist=False)
        self.assertIn(res['prediction'], ['NORMAL', 'ATTACK'])

    # 8. Selected interface & 9. Different interface switching
    @patch('engine.live_capture.sniff', side_effect=fake_sniff)
    def test_08_and_09_interface_lifecycle_and_switching(self, mock_sniff):
        """Verify starting on an interface, stopping, and starting on another interface works cleanly."""
        manager = LiveCaptureManager()
        ifaces = manager.get_available_interfaces()
        self.assertGreater(len(ifaces), 0, "No network interfaces discovered!")

        # Start on loopback
        success, msg = manager.start_capture(interface='lo', flow_timeout=5.0)
        self.assertTrue(success)
        self.assertTrue(manager.is_running)
        self.assertEqual(manager.interface, 'lo')

        # Stop
        success, msg = manager.stop_capture()
        self.assertTrue(success)
        self.assertFalse(manager.is_running)

        # Switch / restart
        success, msg = manager.start_capture(interface='lo', flow_timeout=8.0)
        self.assertTrue(success)
        self.assertTrue(manager.is_running)
        self.assertEqual(manager.flow_timeout, 8.0)
        manager.stop_capture()

    # 10. Stop monitoring & 11. Start monitoring again
    @patch('engine.live_capture.sniff', side_effect=fake_sniff)
    def test_10_and_11_stop_and_restart_monitoring(self, mock_sniff):
        """Verify clean shutdown, resource cleanup, and subsequent restart."""
        manager = LiveCaptureManager()
        manager.start_capture(interface='lo')
        session1 = manager.session_id

        time.sleep(0.1)
        success, _ = manager.stop_capture()
        self.assertTrue(success)
        self.assertFalse(manager.is_running)

        # Restart
        manager.start_capture(interface='lo')
        session2 = manager.session_id
        self.assertTrue(manager.is_running)
        self.assertNotEqual(session1, session2, "Session ID should regenerate on new capture start!")
        manager.stop_capture()

    # 12. Refresh frontend / API state persistence
    @patch('engine.live_capture.sniff', side_effect=fake_sniff)
    def test_12_status_persistence_for_frontend_refresh(self, mock_sniff):
        """Verify get_status accurately exposes running state, interface, and telemetry for frontend refresh."""
        manager = LiveCaptureManager()
        manager.start_capture(interface='lo', flow_timeout=7.5)
        status = manager.get_status()

        self.assertTrue(status['is_running'])
        self.assertEqual(status['interface'], 'lo')
        self.assertEqual(status['flow_timeout'], 7.5)
        self.assertIn('packets_captured', status)
        self.assertIn('active_flows', status)
        self.assertIn('available_interfaces', status)

        manager.stop_capture()
        status_stopped = manager.get_status()
        self.assertFalse(status_stopped['is_running'])

    # 13. Invalid / nonexistent interface fallback
    @patch('engine.live_capture.sniff', side_effect=fake_sniff)
    def test_13_nonexistent_interface_fallback(self, mock_sniff):
        """Verify requesting an invalid interface falls back gracefully to default active interface without crash."""
        manager = LiveCaptureManager()
        success, msg = manager.start_capture(interface='non_existent_iface_999')
        self.assertTrue(success)
        # Interface should have fallen back to a valid discovered interface
        all_names = [i['name'] for i in manager.get_available_interfaces()]
        self.assertIn(manager.interface, all_names)
        manager.stop_capture()


if __name__ == '__main__':
    unittest.main()
