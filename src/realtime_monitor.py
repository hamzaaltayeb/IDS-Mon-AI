import os
import sys
import time
import signal
import argparse
import numpy as np
import pandas as pd
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from engine.pipeline import pipeline
from engine.live_capture import live_capture_manager
from engine.interface_discovery import InterfaceDiscovery
from alerts import AlertSystem

class RealTimeMonitor:
    """
    Unified Real-Time Security Monitoring Controller supporting two distinct modes:
    1. Simulation Mode: Streams flow samples derived from the real UNSW-NB15 benchmark dataset.
    2. Live Network Mode: Captures and aggregates live packets directly from host network interfaces.
    """
    def __init__(self, mode='live', interface=None, bpf_filter='ip', flow_timeout=10.0, debug_capture=False):
        self.mode = mode.lower()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flow_timeout = float(flow_timeout)
        self.debug_capture = bool(debug_capture)
        self.alert_system = AlertSystem()
        self.is_running = False

    @staticmethod
    def print_available_interfaces():
        interfaces = InterfaceDiscovery.get_all_interfaces()
        print("\n=======================================================")
        print("🌐 Available Network Interfaces (Discovered):")
        print("=======================================================")
        for idx, iface in enumerate(interfaces, 1):
            status_str = "UP" if iface['is_up'] else "DOWN"
            print(f"  [{idx}] {iface['name']}")
            print(f"      Type:   {iface['type']}")
            print(f"      Status: {status_str}")
            print(f"      IPv4:   {iface['ipv4']}")
            print(f"      MAC:    {iface['mac']}")
        print("=======================================================\n")

    def run_simulation(self, iterations=None, interval=2.0, batch_size=5):
        """
        Mode 1: Simulation Mode (UNSW-NB15 Benchmark Samples)
        """
        dataset_candidates = [
            os.path.join(SRC_DIR, "data", "UNSW_NB15_testing-set.csv"),
            os.path.join(SRC_DIR, "data", "UNSW_NB15_training-set.csv")
        ]
        
        df_source = None
        for candidate in dataset_candidates:
            if os.path.exists(candidate):
                try:
                    df_source = pd.read_csv(candidate)
                    print(f"[INFO] Loaded benchmark dataset for simulation from: {candidate}")
                    break
                except Exception as e:
                    print(f"[WARNING] Could not read {candidate}: {e}")

        sim_session_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        iter_msg = f"{iterations} iterations" if iterations else "continuous mode (Press Ctrl+C to stop)"
        print(f"\n=======================================================")
        print(f"🚀 AI-NSMS SIMULATION MODE: Streaming benchmark flows")
        print(f"📊 Session ID: {sim_session_id}")
        print(f"📊 Running {iter_msg} at {interval}s interval")
        print(f"=======================================================\n")

        cycle = 0
        self.is_running = True
        try:
            while self.is_running:
                cycle += 1
                if iterations and cycle > iterations:
                    break
                    
                print(f"--- [Simulation Cycle {cycle}] ---")
                
                if df_source is not None and not df_source.empty:
                    samples = df_source.sample(min(batch_size, len(df_source))).copy()
                    for _, row in samples.iterrows():
                        src_ip = f"192.168.1.{np.random.randint(2, 254)}"
                        flow_data = {
                            'source_ip': src_ip,
                            'destination_ip': '10.0.0.1',
                            'protocol': 'TCP' if str(row.get('proto', 'tcp')).lower() == 'tcp' else 'UDP',
                            'destination_port': int(80 if row.get('service') == 'http' else (443 if row.get('service') == 'ssl' else (22 if row.get('service') == 'ssh' else 8080))),
                            'flow_duration': float(row.get('dur', 0.1)),
                            'total_flow_size': float(row.get('sbytes', 1000) + row.get('dbytes', 1000)),
                            'average_packet_size': float(row.get('smean', 100)),
                            'std_packet_size': float(row.get('sjit', 0)),
                            'packet_count': int(row.get('spkts', 10) + row.get('dpkts', 10)),
                            'average_inter_arrival_time': float(row.get('sinpkt', 0.01)),
                            'maximum_inter_arrival_time': float(row.get('dinpkt', 0.05)),
                            'packets_per_second': float(row.get('rate', 50)),
                            'bytes_per_second': float(row.get('sload', 5000) / 8),
                            'traffic_source': 'simulation',
                            'session_id': sim_session_id
                        }
                        res = pipeline.process_flow(flow_data, persist=True)
                        if res.get('prediction') == 'ATTACK':
                            self.alert_system.trigger_alert(src_ip, res.get('attack_type'), confidence=res.get('confidence', 0.9))
                        else:
                            print(f"[SIMULATION] Flow from {src_ip} targeting port {flow_data['destination_port']}: NORMAL (Threat Score: 0/100)")
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[INFO] Simulation stopped by user (Ctrl+C).")
        print("\nSimulation run completed.")

    def run_live(self, duration=None):
        """
        Mode 2: Live Network Monitoring Mode (Captures real network packets from interface)
        """
        all_ifaces = InterfaceDiscovery.get_all_interfaces()
        selected_iface = self.interface or InterfaceDiscovery.get_default_active_interface()
        
        # Get selected interface info
        iface_info = None
        for i in all_ifaces:
            if i['name'] == selected_iface:
                iface_info = i
                break

        iface_names = [i['name'] for i in all_ifaces]

        print(f"\n=======================================================")
        print(f"🛡️  AI-NSMS LIVE NETWORK MONITORING MODE")
        print(f"=======================================================")
        print(f"• Target Interface:    {selected_iface}")
        if iface_info:
            print(f"• Interface Type:      {iface_info['type']}")
            print(f"• Interface Status:    {'UP' if iface_info['is_up'] else 'DOWN'}")
            print(f"• Interface IPv4:      {iface_info['ipv4']}")
            print(f"• Interface MAC:       {iface_info['mac']}")
        print(f"• BPF Capture Filter:  {self.bpf_filter}")
        print(f"• Flow Inactivity Cap: {self.flow_timeout} seconds")
        print(f"• Debug Header Trace:  {'ENABLED' if self.debug_capture else 'DISABLED'}")
        print(f"• Available Interfaces: {', '.join(iface_names)}")
        if selected_iface == 'lo':
            print(f"\n⚠️  WARNING: You are monitoring loopback traffic only (127.0.0.1).")
            print(f"    For real LAN/Wi-Fi traffic, select your physical interface (e.g. wlp108s0).")
        print(f"=======================================================\n")

        success, msg = live_capture_manager.start_capture(
            interface=selected_iface,
            bpf_filter=self.bpf_filter,
            flow_timeout=self.flow_timeout,
            debug_capture=self.debug_capture
        )

        if not success:
            print(f"[ERROR] Failed to start live capture: {msg}")
            return

        self.is_running = True
        start_t = time.time()

        try:
            while self.is_running:
                time.sleep(2.0)
                status = live_capture_manager.get_status()
                
                if status['packets_captured'] == 0:
                    status_line = f"[LIVE MONITORING] NO PACKETS CAPTURED YET (Listening on '{selected_iface}')..."
                else:
                    status_line = (
                        f"[LIVE TELEMETRY] Packets: {status['packets_captured']:,} | "
                        f"Active Flows: {status['active_flows']} | "
                        f"Finalized: {status['finalized_flows']} | "
                        f"Analyzed: {status['analyzed_flows']} | "
                        f"Detections: {status['detections_count']} | "
                        f"Alerts: {status['alerts_count']}"
                    )
                print(status_line)
                
                if duration and (time.time() - start_t) >= duration:
                    break
        except KeyboardInterrupt:
            print("\n[INFO] Live monitoring termination requested by user (Ctrl+C)...")
        finally:
            live_capture_manager.stop_capture()

def main():
    parser = argparse.ArgumentParser(description="AI-NSMS Real-Time Network Security Monitor (Simulation & Live Modes)")
    parser.add_argument("--mode", type=str, choices=['simulation', 'live'], default='live',
                        help="Monitoring mode: 'live' (real packet capture) or 'simulation' (UNSW-NB15 flows)")
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface for live mode (e.g. wlp108s0, eth0, lo)")
    parser.add_argument("-f", "--filter", type=str, default="ip",
                        help="BPF capture filter for live mode (default: 'ip')")
    parser.add_argument("-t", "--flow-timeout", type=float, default=10.0,
                        help="Flow inactivity timeout in seconds (default: 10.0)")
    parser.add_argument("--debug-capture", action="store_true",
                        help="Enable packet debug summary logging (headers only, no payloads)")
    parser.add_argument("-l", "--list-interfaces", action="store_true",
                        help="List all discovered network interfaces and exit")
    parser.add_argument("-n", "--iterations", type=int, default=None,
                        help="Number of cycles/seconds to run (default: continuous)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Interval in seconds for simulation mode (default: 2.0)")
    args = parser.parse_args()

    if args.list_interfaces:
        RealTimeMonitor.print_available_interfaces()
        return

    monitor = RealTimeMonitor(
        mode=args.mode,
        interface=args.interface,
        bpf_filter=args.filter,
        flow_timeout=args.flow_timeout,
        debug_capture=args.debug_capture
    )

    if args.mode == 'live':
        monitor.run_live(duration=args.iterations)
    else:
        monitor.run_simulation(iterations=args.iterations, interval=args.interval)

if __name__ == "__main__":
    main()
