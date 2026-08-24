import time
import math
import threading
import numpy as np
from collections import defaultdict

class FlowRecord:
    """
    Maintains bidirectional state and statistics for a single network flow session.
    """
    def __init__(self, src_ip, dst_ip, proto, src_port=0, dst_port=0, start_time=None):
        self.initiator_ip = src_ip
        self.responder_ip = dst_ip
        self.proto = proto
        self.initiator_port = src_port
        self.responder_port = dst_port
        
        # Primary reference endpoints
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        
        self.start_time = start_time if start_time is not None else time.time()
        self.last_seen = self.start_time
        self.teardown_time = None
        
        self.packet_count = 0
        self.total_bytes = 0
        self.forward_packets = 0
        self.reverse_packets = 0
        self.forward_bytes = 0
        self.reverse_bytes = 0
        
        self.packet_lengths = []
        self.arrival_times = []
        self.is_terminated = False

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, pkt_len, pkt_time=None, tcp_flags=None):
        if pkt_time is None:
            pkt_time = time.time()
            
        self.last_seen = pkt_time
        self.packet_count += 1
        self.total_bytes += pkt_len
        self.packet_lengths.append(pkt_len)
        self.arrival_times.append(pkt_time)

        # Track forward vs reverse traffic
        if src_ip == self.initiator_ip and src_port == self.initiator_port:
            self.forward_packets += 1
            self.forward_bytes += pkt_len
        else:
            self.reverse_packets += 1
            self.reverse_bytes += pkt_len

        # Check TCP session termination (FIN: 0x01, RST: 0x04)
        if tcp_flags is not None:
            if tcp_flags & 0x01 or tcp_flags & 0x04:
                if self.teardown_time is None:
                    self.teardown_time = pkt_time

    def calculate_features(self):
        """
        Calculates the 11 standard flow features with strict mathematical and physical validity:
        - For single-packet flows (count <= 1), duration, pps, bps, and IAT are 0.0 (insufficient temporal evidence).
        - For multi-packet flows (count >= 2), duration is computed from real timestamps.
        """
        pkt_count = self.packet_count
        total_size = float(self.total_bytes)
        
        if pkt_count <= 1:
            duration = 0.0
            pps = 0.0
            bps = 0.0
            avg_size = total_size if pkt_count == 1 else 0.0
            std_size = 0.0
            avg_iat = 0.0
            max_iat = 0.0
            rate_status = "INSUFFICIENT_TEMPORAL_EVIDENCE"
        else:
            raw_duration = self.last_seen - self.start_time
            duration = max(1e-3, raw_duration)  # Physical floor: 1ms
            pps = float(pkt_count / duration)
            bps = float(total_size / duration)
            avg_size = float(total_size / pkt_count)
            
            # Thread-safe snapshot of packet metrics
            pkt_lens = list(self.packet_lengths)
            arr_times = list(self.arrival_times)
            
            std_size = float(np.std(pkt_lens)) if len(pkt_lens) > 1 else 0.0
            
            if len(arr_times) > 1:
                iats = np.diff(arr_times)
                avg_iat = float(np.mean(iats)) if len(iats) > 0 else 0.0
                max_iat = float(np.max(iats)) if len(iats) > 0 else 0.0
            else:
                avg_iat = 0.0
                max_iat = 0.0
            rate_status = "CALCULATED"

        # Determine logical service destination port (favor well-known service ports < 1024 or registered < 49152)
        service_port = self.dst_port
        if self.src_port in [80, 443, 53, 22, 21, 25, 110, 143, 3389, 3306, 5432, 8080, 8443] and self.dst_port > 1024:
            service_port = self.src_port

        return {
            'source_ip': self.initiator_ip,
            'destination_ip': self.responder_ip,
            'protocol': self.proto,
            'source_port': int(self.src_port),
            'destination_port': int(service_port),
            'flow_duration': round(duration, 4),
            'total_flow_size': round(total_size, 2),
            'average_packet_size': round(avg_size, 2),
            'std_packet_size': round(std_size, 2),
            'packet_count': int(pkt_count),
            'forward_packets': int(self.forward_packets),
            'reverse_packets': int(self.reverse_packets),
            'average_inter_arrival_time': round(avg_iat, 5),
            'maximum_inter_arrival_time': round(max_iat, 5),
            'packets_per_second': round(pps, 2),
            'bytes_per_second': round(bps, 2),
            'rate_status': rate_status
        }


class BehavioralTracker:
    """
    Maintains short-window multi-flow behavioral statistics for correlation:
    - Port scan detection (distinct ports probed per source IP in window)
    - Brute force connection bursts per source IP on auth ports
    - DDoS aggregate target flood rates
    """
    def __init__(self, window_seconds=15.0):
        self.window = window_seconds
        self.src_ports_probed = defaultdict(list) # src_ip -> [(timestamp, dst_port)]
        self.auth_bursts = defaultdict(list)      # (src_ip, dst_port) -> [timestamp]
        self.dst_packet_rates = defaultdict(list)  # dst_ip -> [(timestamp, count, bytes)]
        self.lock = threading.Lock()

    def record_packet(self, src_ip, dst_ip, proto, dst_port, pkt_len, now):
        with self.lock:
            cutoff = now - self.window
            
            # 1. Track probed ports
            probes = self.src_ports_probed[src_ip]
            probes.append((now, dst_port))
            self.src_ports_probed[src_ip] = [p for p in probes if p[0] >= cutoff]

            # 2. Track auth service attempts
            if dst_port in [22, 21, 3389, 23, 3306, 5432]:
                attempts = self.auth_bursts[(src_ip, dst_port)]
                attempts.append(now)
                self.auth_bursts[(src_ip, dst_port)] = [t for t in attempts if t >= cutoff]

            # 3. Track target packet rates
            rates = self.dst_packet_rates[dst_ip]
            rates.append((now, 1, pkt_len))
            self.dst_packet_rates[dst_ip] = [r for r in rates if r[0] >= cutoff]

    def get_port_scan_count(self, src_ip, now):
        with self.lock:
            cutoff = now - self.window
            probes = [p[1] for p in self.src_ports_probed.get(src_ip, []) if p[0] >= cutoff]
            return len(set(probes))

    def get_auth_attempt_count(self, src_ip, dst_port, now):
        with self.lock:
            cutoff = now - self.window
            attempts = [t for t in self.auth_bursts.get((src_ip, dst_port), []) if t >= cutoff]
            return len(attempts)

    def get_target_traffic_rate(self, dst_ip, now):
        with self.lock:
            cutoff = now - self.window
            rates = [r for r in self.dst_packet_rates.get(dst_ip, []) if r[0] >= cutoff]
            total_pkts = sum(r[1] for r in rates)
            total_bytes = sum(r[2] for r in rates)
            dur = max(1.0, self.window)
            return (total_pkts / dur), (total_bytes / dur)


class FlowTable:
    """
    Thread-safe in-memory table for active network flows using Canonical Bidirectional Session Keys.
    """
    def __init__(self, flow_timeout=10.0, max_active_flows=10000, max_flow_duration=60.0, teardown_grace_period=1.0):
        self.flow_timeout = float(flow_timeout)
        self.max_active_flows = int(max_active_flows)
        self.max_flow_duration = float(max_flow_duration)
        self.teardown_grace_period = float(teardown_grace_period)
        self.flows = {}
        self.behavioral = BehavioralTracker(window_seconds=15.0)
        self.lock = threading.Lock()

    @staticmethod
    def _get_canonical_session_key(src_ip, dst_ip, proto, src_port, dst_port):
        """
        Generates a symmetric canonical 5-tuple key so forward and reverse packets
        of the same session map into the exact same FlowRecord.
        """
        proto_str = str(proto).upper()
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, proto_str, src_port, dst_port)
        else:
            return (dst_ip, src_ip, proto_str, dst_port, src_port)

    def process_packet(self, src_ip, dst_ip, proto, dst_port, src_port, pkt_len, pkt_time=None, tcp_flags=None):
        if pkt_time is None:
            pkt_time = time.time()

        canonical_key = self._get_canonical_session_key(src_ip, dst_ip, proto, src_port, dst_port)
        
        # Record behavioral telemetry
        self.behavioral.record_packet(src_ip, dst_ip, proto, dst_port, pkt_len, pkt_time)

        with self.lock:
            if canonical_key not in self.flows:
                if len(self.flows) >= self.max_active_flows:
                    oldest_key = min(self.flows.keys(), key=lambda k: self.flows[k].last_seen)
                    del self.flows[oldest_key]

                self.flows[canonical_key] = FlowRecord(src_ip, dst_ip, proto, src_port, dst_port, start_time=pkt_time)

            flow = self.flows[canonical_key]
            flow.add_packet(src_ip, dst_ip, src_port, dst_port, pkt_len, pkt_time, tcp_flags)

    def get_expired_flows(self, current_time=None):
        """
        Extracts and removes expired or gracefully terminated flows.
        """
        if current_time is None:
            current_time = time.time()

        expired_list = []
        with self.lock:
            keys_to_remove = []
            for key, flow in self.flows.items():
                idle_time = current_time - flow.last_seen
                duration = current_time - flow.start_time
                
                # Check teardown grace expiration
                teardown_expired = False
                if flow.teardown_time is not None:
                    if (current_time - flow.teardown_time) >= self.teardown_grace_period:
                        teardown_expired = True

                # Expiration conditions:
                if idle_time >= self.flow_timeout or teardown_expired or duration >= self.max_flow_duration:
                    features = flow.calculate_features()
                    
                    # Attach multi-flow behavioral context
                    features['context_ports_probed'] = self.behavioral.get_port_scan_count(features['source_ip'], current_time)
                    features['context_auth_attempts'] = self.behavioral.get_auth_attempt_count(features['source_ip'], features['destination_port'], current_time)
                    tgt_pps, tgt_bps = self.behavioral.get_target_traffic_rate(features['destination_ip'], current_time)
                    features['context_target_pps'] = tgt_pps
                    features['context_target_bps'] = tgt_bps
                    
                    expired_list.append(features)
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.flows[key]

        return expired_list

    def flush_all_flows(self):
        flushed = []
        now = time.time()
        with self.lock:
            for flow in self.flows.values():
                f = flow.calculate_features()
                f['context_ports_probed'] = self.behavioral.get_port_scan_count(f['source_ip'], now)
                f['context_auth_attempts'] = self.behavioral.get_auth_attempt_count(f['source_ip'], f['destination_port'], now)
                tgt_pps, tgt_bps = self.behavioral.get_target_traffic_rate(f['destination_ip'], now)
                f['context_target_pps'] = tgt_pps
                f['context_target_bps'] = tgt_bps
                flushed.append(f)
            self.flows.clear()
        return flushed

    def get_active_flow_count(self):
        with self.lock:
            return len(self.flows)
