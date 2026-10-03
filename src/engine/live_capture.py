import os
import sys
import time
import uuid
import threading
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from .flow_collector import FlowTable
from .pipeline import pipeline
from .interface_discovery import InterfaceDiscovery

class LiveCaptureManager:
    """
    Real-Time Network Packet Sniffing, Flow Extraction,
    and Automated AI Detection Ingestion Layer for AI-NSMS.
    """
    _instance = None

    def __init__(self, interface='wlp108s0', bpf_filter='ip', flow_timeout=10.0, debug_capture=False):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flow_timeout = float(flow_timeout)
        self.debug_capture = bool(debug_capture)
        
        self.flow_table = FlowTable(flow_timeout=self.flow_timeout)
        self.is_running = False
        self.session_id = ""
        
        self.capture_thread = None
        self.dispatch_thread = None
        self.stop_event = threading.Event()
        
        # Telemetry metrics
        self.packets_captured = 0
        self.packets_parsed = 0
        self.finalized_flows = 0
        self.analyzed_flows = 0
        self.early_analyzed_flows = 0
        self.detections_count = 0
        self.alerts_count = 0
        self.start_time = None
        self.stop_time = None
        self.last_error = None
        self.is_loopback_warning = False
        self.lock = threading.Lock()

    def get_available_interfaces(self):
        return InterfaceDiscovery.get_all_interfaces()

    def _packet_callback(self, pkt):
        """
        Callback invoked by Scapy for every captured frame on the wire.
        """
        if not self.is_running:
            return

        with self.lock:
            self.packets_captured += 1

        src_ip = '127.0.0.1'
        dst_ip = '127.0.0.1'
        proto = 'OTHER'
        dst_port = 0
        src_port = 0
        tcp_flags = None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return  # Non-IP frames ignored

        if TCP in pkt:
            proto = 'TCP'
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            proto = 'UDP'
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = 'ICMP'
            dst_port = 0

        pkt_len = len(pkt)
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        with self.lock:
            self.packets_parsed += 1

        # Diagnostic debug mode logging
        if self.debug_capture:
            proto_label = f"[{proto}]"
            if proto == 'UDP' and (dst_port == 53 or src_port == 53):
                proto_label = "[DNS]"
            elif proto == 'TCP' and (dst_port == 443 or src_port == 443):
                proto_label = "[HTTPS]"
            elif proto == 'TCP' and (dst_port == 80 or src_port == 80):
                proto_label = "[HTTP]"
            print(f"{proto_label} {src_ip}:{src_port} → {dst_ip}:{dst_port} | Length: {pkt_len} bytes")

        self.flow_table.process_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            dst_port=dst_port,
            src_port=src_port,
            pkt_len=pkt_len,
            pkt_time=pkt_time,
            tcp_flags=tcp_flags
        )

    def _dispatch_worker(self):
        """
        Background worker that continuously inspects FlowTable for completed flows,
        extracts the 11 features, and feeds them into AIDetectionPipeline.
        Provides periodic diagnostic telemetry and instant threat logging (Task 9).
        """
        last_telemetry_log = time.time()
        while not self.stop_event.is_set():
            try:
                actionable_flows = self.flow_table.get_expired_flows()
                for flow_data in actionable_flows:
                    flow_data['traffic_source'] = 'live'
                    flow_data['session_id'] = self.session_id
                    is_active = (flow_data.get('rate_status') == 'ACTIVE_SNAPSHOT')

                    with self.lock:
                        if not is_active:
                            self.finalized_flows += 1

                    # AI Inference & DB Persistence
                    result = pipeline.process_flow(flow_data, persist=True)

                    with self.lock:
                        self.analyzed_flows += 1
                        if is_active:
                            self.early_analyzed_flows += 1
                        if result.get('prediction') == 'ATTACK':
                            self.detections_count += 1
                        if result.get('alert_id'):
                            self.alerts_count += 1

                    # Instant threat diagnostic logging (Task 9)
                    if result.get('prediction') == 'ATTACK' and result.get('threat_score', 0) >= 50:
                        print(f"[THREAT DETECTED] Flow #{result.get('detection_id', 'N/A')}: "
                              f"{flow_data['source_ip']}:{flow_data['source_port']} → {flow_data['destination_ip']}:{flow_data['destination_port']} "
                              f"({flow_data['protocol']}) | Pkts: {flow_data['packet_count']} | Dur: {flow_data['flow_duration']:.2f}s | "
                              f"Type: {result.get('attack_type')} | Model: {result.get('model_prediction')} ({result.get('model_probability', 0):.2f}) | "
                              f"Score: {result.get('threat_score')}/100 | Severity: {result.get('severity')}")
                    elif self.debug_capture:
                        print(f"[FLOW ANALYZED] {flow_data['source_ip']} → {flow_data['destination_ip']}:{flow_data['destination_port']} ({flow_data['protocol']}) | Pkts: {flow_data['packet_count']} | Result: {result.get('attack_type')} (Score: {result.get('threat_score')}/100)")

                # Concise Periodic Telemetry Logging (Task 9)
                now = time.time()
                if (now - last_telemetry_log) >= 3.0 and self.packets_captured > 0:
                    active_cnt = self.flow_table.get_active_flow_count()
                    print(f"[MONITOR TELEMETRY] Packets: {self.packets_captured:,} | Active Flows: {active_cnt:,} | "
                          f"Early Analyzed: {self.early_analyzed_flows:,} | Finalized: {self.finalized_flows:,} | "
                          f"Total Analyzed: {self.analyzed_flows:,} | Detections: {self.detections_count:,} | Alerts: {self.alerts_count:,}")
                    last_telemetry_log = now

            except Exception as e:
                print(f"[ERROR] Live capture flow dispatch error: {e}")
            time.sleep(0.5)

    def _capture_worker(self):
        """
        Executes Scapy packet sniffing with periodic timeout for responsive graceful termination.
        """
        try:
            filter_desc = f"Filter: '{self.bpf_filter}'" if self.bpf_filter else "No filter (All IP/IPv6)"
            print(f"[INFO] Sniffer listening on interface: '{self.interface}' ({filter_desc})")
            err_count = 0
            while not self.stop_event.is_set():
                try:
                    sniff_filter = self.bpf_filter if (self.bpf_filter and self.bpf_filter.strip()) else None
                    sniff(
                        iface=self.interface,
                        prn=self._packet_callback,
                        filter=sniff_filter,
                        store=False,
                        timeout=1.0,
                        stop_filter=lambda p: self.stop_event.is_set()
                    )
                    err_count = 0
                except (KeyboardInterrupt, SystemExit):
                    break
                except (PermissionError, OSError) as e:
                    err_msg = str(e).lower()
                    if "operation not permitted" in err_msg or "permission denied" in err_msg:
                        self.last_error = "Permission denied: Packet capture requires elevated privileges (CAP_NET_RAW). Re-run with: sudo ./run.sh"
                        print(f"\n[FATAL ERROR] {self.last_error}\n")
                        break
                    err_count += 1
                    self.last_error = f"Sniffing socket error on '{self.interface}': {e}"
                    if err_count <= 2:
                        print(f"[WARNING] {self.last_error}")
                    time.sleep(0.5)
                except Exception as e:
                    if self.stop_event.is_set():
                        break
                    err_count += 1
                    self.last_error = f"Sniffing error on '{self.interface}': {e}"
                    if err_count <= 2:
                        print(f"[WARNING] {self.last_error}")
                    time.sleep(0.5)
        except Exception as e:
            if not self.stop_event.is_set():
                self.last_error = f"Sniffing initialization error: {e}"
                print(f"[ERROR] {self.last_error}")
        finally:
            self.is_running = False


    def start_capture(self, interface=None, bpf_filter=None, flow_timeout=10.0, debug_capture=False):
        """
        Starts real-time live network packet capture.
        """
        if self.is_running:
            return True, "Live capture is already active."

        # Interface selection & validation
        all_ifaces = InterfaceDiscovery.get_all_interfaces()
        iface_names = [i['name'] for i in all_ifaces]
        
        target_iface = interface or self.interface or InterfaceDiscovery.get_default_active_interface()
        if target_iface not in iface_names and iface_names:
            target_iface = InterfaceDiscovery.get_default_active_interface()

        self.interface = target_iface
        self.bpf_filter = bpf_filter if bpf_filter is not None else self.bpf_filter
        self.flow_timeout = float(flow_timeout)
        self.debug_capture = bool(debug_capture)
        pipeline.enable_debug_logging = self.debug_capture
        self.is_loopback_warning = (self.interface == 'lo')
        
        # New Monitoring Session ID
        self.session_id = f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.flow_table = FlowTable(flow_timeout=self.flow_timeout)

        # Reset counters
        self.packets_captured = 0
        self.packets_parsed = 0
        self.finalized_flows = 0
        self.analyzed_flows = 0
        self.early_analyzed_flows = 0
        self.detections_count = 0
        self.alerts_count = 0
        self.last_error = None
        self.start_time = time.time()
        self.stop_time = None
        self.stop_event.clear()
        self.is_running = True

        print(f"\n=======================================================")
        print(f"[INFO] Starting live packet capture")
        print(f"[INFO] Interface:       {self.interface}")
        print(f"[INFO] Capture filter:  {self.bpf_filter}")
        print(f"[INFO] Flow timeout:    {self.flow_timeout}s")
        print(f"[INFO] Session ID:      {self.session_id}")
        if self.is_loopback_warning:
            print(f"[WARNING] You are monitoring loopback traffic only (127.0.0.1).")
        print(f"[INFO] Sniffer started")
        print(f"=======================================================\n")

        # Launch workers
        self.dispatch_thread = threading.Thread(target=self._dispatch_worker, daemon=True, name="FlowDispatcher")
        self.dispatch_thread.start()

        self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True, name="PacketCapture")
        self.capture_thread.start()

        return True, f"Live capture started on interface '{self.interface}'"

    def stop_capture(self):
        """
        Stops live packet capture gracefully and flushes all remaining flows to the AI pipeline.
        """
        with self.lock:
            if not self.is_running and getattr(self, '_shutdown_completed', False):
                return True, "Live capture is not running."
            if getattr(self, '_shutdown_in_progress', False):
                return True, "Shutdown already in progress."
            self._shutdown_in_progress = True
            self.is_running = False

        print("\n[INFO] Shutdown requested: Stopping Live Network Capture...")
        self.stop_event.set()
        self.stop_time = time.time()

        # Wait briefly for background capture and dispatch threads to conclude
        try:
            if self.dispatch_thread and self.dispatch_thread.is_alive():
                self.dispatch_thread.join(timeout=0.8)
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=0.8)
        except (KeyboardInterrupt, SystemExit):
            pass

        # Safely flush and process any remaining flows in the table
        try:
            print("[INFO] Flushing remaining flows to AI pipeline...")
            remaining_flows = self.flow_table.flush_all_flows()
            for flow_data in remaining_flows:
                flow_data['traffic_source'] = 'live'
                flow_data['session_id'] = self.session_id
                with self.lock:
                    self.finalized_flows += 1

                result = pipeline.process_flow(flow_data, persist=True)
                with self.lock:
                    self.analyzed_flows += 1
                    if result.get('prediction') == 'ATTACK':
                        self.detections_count += 1
                    if result.get('alert_id'):
                        self.alerts_count += 1
            print(f"[INFO] Remaining flows processed successfully ({len(remaining_flows)} flows finalized).")
        except (KeyboardInterrupt, SystemExit):
            print("\n[INFO] Remaining flows flushed safely.")
        except Exception as e:
            print(f"[ERROR] Error during final flow flush: {e}")

        uptime = round(self.stop_time - self.start_time, 2) if self.start_time else 0
        print("\n=======================================================")
        print(f"🛡️  LIVE MONITORING STOPPED SUCCESSFULLY")
        print(f"• Interface:            {self.interface}")
        print(f"• Session ID:           {self.session_id}")
        print(f"• Packets Captured:     {self.packets_captured:,}")
        print(f"• Packets Parsed:       {self.packets_parsed:,}")
        print(f"• Flows Finalized:      {self.finalized_flows:,}")
        print(f"• Flows Analyzed:       {self.analyzed_flows:,}")
        print(f"• Attack Detections:    {self.detections_count:,}")
        print(f"• Security Alerts:      {self.alerts_count:,}")
        print(f"• Total Uptime:         {uptime} seconds")
        print("=======================================================\n")

        with self.lock:
            self._shutdown_in_progress = False
            self._shutdown_completed = True

        return True, "Live capture stopped successfully."

    def get_status(self):
        """
        Returns live telemetry status dictionary.
        """
        with self.lock:
            uptime = time.time() - self.start_time if (self.is_running and self.start_time) else 0
            if not self.is_running and self.stop_time and self.start_time:
                uptime = self.stop_time - self.start_time

            # Selected interface metadata
            iface_info = None
            for i in InterfaceDiscovery.get_all_interfaces():
                if i['name'] == self.interface:
                    iface_info = i
                    break

            return {
                'is_running': self.is_running,
                'interface': self.interface,
                'interface_details': iface_info or {'name': self.interface, 'type': 'Unknown', 'ipv4': 'None', 'is_up': True},
                'bpf_filter': self.bpf_filter,
                'flow_timeout': self.flow_timeout,
                'session_id': self.session_id,
                'packets_captured': self.packets_captured,
                'packets_parsed': self.packets_parsed,
                'active_flows': self.flow_table.get_active_flow_count(),
                'finalized_flows': self.finalized_flows,
                'analyzed_flows': self.analyzed_flows,
                'early_analyzed_flows': self.early_analyzed_flows,
                'detections_count': self.detections_count,
                'alerts_count': self.alerts_count,
                'uptime_seconds': round(uptime, 1),
                'last_error': self.last_error,
                'is_loopback_warning': self.is_loopback_warning,
                'available_interfaces': InterfaceDiscovery.get_all_interfaces()
            }

# Global singleton live capture manager instance
live_capture_manager = LiveCaptureManager()
