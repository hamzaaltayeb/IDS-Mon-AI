import os
import sys
import time
import signal
import argparse

# Early graceful shutdown trap
def _early_signal_trap(signum, frame):
    print("\n[INFO] Termination requested (Ctrl+C / SIGINT). Exiting cleanly...")
    sys.exit(0)

signal.signal(signal.SIGINT, _early_signal_trap)
signal.signal(signal.SIGTERM, _early_signal_trap)

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
    Real-Time AI-Based Network Security Monitor.

    Captures live packets from a host network interface, aggregates
    bidirectional flows, extracts 9 statistical features per flow,
    classifies them via a multi-tiered AI engine (Random Forest +
    IsolationForest + Behavioral Heuristics), and triggers alerts
    on detected threats (DDoS, Port Scan, Brute Force).

    Runtime path: REAL LIVE NETWORK TRAFFIC ONLY.
    Dataset/training code lives in src/train_model.py (offline only).
    """

    def __init__(self, interface=None, bpf_filter='ip', flow_timeout=10.0, debug_capture=False):
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

    def run_live(self, duration=None):
        """
        Live Network Monitoring Mode — captures real network packets from the selected interface.
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

        # Register graceful signal handlers
        def _signal_handler(signum, frame):
            if not self.is_running:
                print("\n[INFO] Shutdown already in progress, please wait...")
                return
            print("\n[INFO] Live monitoring termination signal received (Ctrl+C / SIGINT)...")
            self.is_running = False

        original_sigint = signal.signal(signal.SIGINT, _signal_handler)
        original_sigterm = signal.signal(signal.SIGTERM, _signal_handler)

        try:
            tip_printed = False
            while self.is_running:
                time.sleep(1.0)
                status = live_capture_manager.get_status()

                # If capture stopped unexpectedly (e.g. permission error)
                if not status.get('is_running') and self.is_running:
                    err = status.get('last_error') or "Live packet sniffer stopped unexpectedly."
                    print(f"\n❌ [CAPTURE HALTED] {err}\n")
                    break

                if status['packets_captured'] == 0:
                    if status.get('last_error'):
                        status_line = f"⚠️  [CAPTURE ERROR] {status['last_error']}"
                    else:
                        status_line = f"[LIVE MONITORING] Listening on '{selected_iface}'... (Awaiting incoming/outgoing packets)"
                        if not tip_printed:
                            print(f"\n💡 [TIP] To see packets flowing on '{selected_iface}', browse any website (Google, YouTube) or run: curl -s https://google.com > /dev/null\n")
                            tip_printed = True
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
        except (KeyboardInterrupt, SystemExit):
            print("\n[INFO] Live monitoring termination requested...")
        finally:
            self.is_running = False
            try:
                live_capture_manager.stop_capture()
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                print(f"[ERROR] Error stopping live capture: {e}")
            finally:
                # Restore original handlers
                try:
                    signal.signal(signal.SIGINT, original_sigint)
                    signal.signal(signal.SIGTERM, original_sigterm)
                except Exception:
                    pass


def main():
    # Global Graceful Signal Handler for Ctrl+C
    _shutting_down = False

    def _global_sigint_handler(signum, frame):
        nonlocal _shutting_down
        if _shutting_down:
            print("\n[INFO] Shutdown already in progress, please wait...")
            return
        _shutting_down = True
        print("\n[INFO] Termination requested by user (Ctrl+C / SIGINT)...")
        try:
            live_capture_manager.stop_capture()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _global_sigint_handler)
    signal.signal(signal.SIGTERM, _global_sigint_handler)

    parser = argparse.ArgumentParser(
        description="AI-NSMS Real-Time Network Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python realtime_monitor.py                        # Auto-detect interface
  sudo python realtime_monitor.py -i wlp108s0           # Specific Wi-Fi interface
  sudo python realtime_monitor.py -i eth0 -t 5.0        # Ethernet, 5s flow timeout
  sudo python realtime_monitor.py -l                     # List available interfaces
  sudo python realtime_monitor.py --debug-capture        # Verbose packet header logging
        """
    )
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface (e.g. wlp108s0, eth0, lo). Auto-detected if not specified.")
    parser.add_argument("-f", "--filter", type=str, default="ip",
                        help="BPF capture filter (default: 'ip'). Examples: 'tcp', 'udp', 'not port 22'")
    parser.add_argument("-t", "--flow-timeout", type=float, default=10.0,
                        help="Flow inactivity timeout in seconds (default: 10.0)")
    parser.add_argument("--debug-capture", action="store_true",
                        help="Enable packet-level debug logging (header summaries only, no payload)")
    parser.add_argument("-l", "--list-interfaces", action="store_true",
                        help="List all discovered network interfaces and exit")
    parser.add_argument("-n", "--duration", type=int, default=None,
                        help="Run duration in seconds (default: continuous until Ctrl+C)")
    args = parser.parse_args()

    if args.list_interfaces:
        RealTimeMonitor.print_available_interfaces()
        return

    monitor = RealTimeMonitor(
        interface=args.interface,
        bpf_filter=args.filter,
        flow_timeout=args.flow_timeout,
        debug_capture=args.debug_capture
    )

    try:
        monitor.run_live(duration=args.duration)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

