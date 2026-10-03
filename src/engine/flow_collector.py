import time
import math
import threading
import numpy as np
from collections import OrderedDict, defaultdict

class FlowRecord:
    """
    Maintains bidirectional state and statistics for a single network flow session.
    Supports controlled multi-stage analysis while keeping track of evaluation state.
    """
    def __init__(self, src_ip, dst_ip, proto, src_port=0, dst_port=0, start_time=None):
        self.initiator_ip = src_ip
        self.responder_ip = dst_ip
        self.proto = str(proto).upper()
        self.initiator_port = int(src_port)
        self.responder_port = int(dst_port)
        
        # Primary reference endpoints
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        
        self.start_time = start_time if start_time is not None else time.time()
        self.last_seen = self.start_time
        self.teardown_time = None
        
        # Controlled analysis state tracking (prevents duplicate ML inference)
        self.last_analyzed_time = self.start_time
        self.last_analyzed_pkts = 0
        self.analysis_count = 0
        self.is_analyzed_active = False
        self.is_syn_only = (self.proto == 'TCP')
        
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

        # Check TCP flags: identify non-SYN traffic and session teardowns
        if tcp_flags is not None and self.proto == 'TCP':
            # If not a pure SYN packet (e.g. ACK, PSH, data, or FIN/RST), it's not a pure SYN probe
            if not (tcp_flags & 0x02) or (tcp_flags & 0x10):
                self.is_syn_only = False
            
            # Check TCP session termination (FIN: 0x01, RST: 0x04)
            if (tcp_flags & 0x01) or (tcp_flags & 0x04):
                if self.teardown_time is None:
                    self.teardown_time = pkt_time

    def calculate_features(self, current_time=None):
        """
        Calculates the 11 standard flow features with strict mathematical and physical validity:
        - For single-packet flows analyzed during active life, duration is derived from elapsed window.
        - For multi-packet flows, duration is computed from real timestamps.
        - Preserves exact feature order and compatibility for StandardScaler.
        """
        pkt_count = self.packet_count
        total_size = float(self.total_bytes)
        
        if pkt_count <= 1:
            if current_time is not None and current_time > self.start_time:
                raw_duration = current_time - self.start_time
                duration = max(1e-3, raw_duration)
                pps = float(pkt_count / duration)
                bps = float(total_size / duration)
                avg_size = total_size if pkt_count == 1 else 0.0
                std_size = 0.0
                avg_iat = 0.0
                max_iat = 0.0
                rate_status = "ACTIVE_WINDOW"
            else:
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
            'rate_status': rate_status,
            'is_syn_only': self.is_syn_only
        }


class BehavioralTracker:
    """
    Maintains short-window multi-flow behavioral statistics for correlation:
    - Per-target port scan detection (distinct ports probed per source IP against a specific target host)
    - Brute force connection bursts per source IP on auth ports
    - DDoS aggregate target flood rates using O(1) time-bucketed aggregation
    """
    # Standard outbound client destinations that should NEVER be flagged as port scan targets
    STANDARD_CLIENT_PORTS = {53, 123, 80, 443, 8080, 8443}

    def __init__(self, window_seconds=15.0):
        self.window = float(window_seconds)
        # (src_ip, dst_ip) -> [(timestamp, dst_port)]
        self.src_target_probes = defaultdict(list)
        # (src_ip, dst_port) -> [timestamp]
        self.auth_bursts = defaultdict(list)
        # dst_ip -> {bucket_sec: {'pkts': count, 'bytes': bytes}}
        self.dst_buckets = defaultdict(lambda: defaultdict(lambda: {'pkts': 0, 'bytes': 0}))
        self.lock = threading.Lock()

    def record_packet(self, src_ip, dst_ip, proto, dst_port, pkt_len, now, tcp_flags=None):
        with self.lock:
            cutoff = now - self.window
            current_bucket = int(now)

            # 1. Track probed ports per TARGET host (src_ip -> dst_ip)
            # Only count actual probe attempts:
            # - For TCP: SYN (0x02) without ACK (0x10) and without RST (0x04)
            # - Exclude standard outbound client services unless dst_ip is receiving multiple non-standard ports
            is_scan_probe = False
            if proto == 'TCP' and tcp_flags is not None:
                if (tcp_flags & 0x02) and not (tcp_flags & 0x04) and not (tcp_flags & 0x10):
                    is_scan_probe = True
            elif proto == 'UDP':
                if dst_port not in self.STANDARD_CLIENT_PORTS:
                    is_scan_probe = True

            if is_scan_probe:
                key = (src_ip, dst_ip)
                probes = self.src_target_probes[key]
                probes.append((now, dst_port))
                self.src_target_probes[key] = [p for p in probes if p[0] >= cutoff]

            # 2. Track auth service attempts (initial connection attempts / handshakes)
            if dst_port in [22, 21, 3389, 23, 3306, 5432]:
                is_auth_init = True
                if proto == 'TCP' and tcp_flags is not None:
                    is_auth_init = bool(tcp_flags & 0x02) or bool(tcp_flags & 0x04)
                if is_auth_init:
                    attempts = self.auth_bursts[(src_ip, dst_port)]
                    attempts.append(now)
                    self.auth_bursts[(src_ip, dst_port)] = [t for t in attempts if t >= cutoff]

            # 3. Track aggregate target traffic rate in O(1) integer second buckets
            b_dict = self.dst_buckets[dst_ip]
            b_dict[current_bucket]['pkts'] += 1
            b_dict[current_bucket]['bytes'] += pkt_len
            
            # Prune old buckets older than cutoff
            old_buckets = [b for b in b_dict.keys() if b < int(cutoff)]
            for ob in old_buckets:
                del b_dict[ob]

    def get_port_scan_count(self, src_ip, dst_ip, now):
        with self.lock:
            cutoff = now - self.window
            key = (src_ip, dst_ip)
            probes = [p[1] for p in self.src_target_probes.get(key, []) if p[0] >= cutoff]
            return len(set(probes))

    def get_auth_attempt_count(self, src_ip, dst_port, now):
        with self.lock:
            cutoff = now - self.window
            attempts = [t for t in self.auth_bursts.get((src_ip, dst_port), []) if t >= cutoff]
            return len(attempts)

    def get_target_traffic_rate(self, dst_ip, now):
        with self.lock:
            cutoff = int(now - self.window)
            b_dict = self.dst_buckets.get(dst_ip, {})
            recent = {b: v for b, v in b_dict.items() if b >= cutoff}
            total_pkts = sum(v['pkts'] for v in recent.values())
            total_bytes = sum(v['bytes'] for v in recent.values())
            # Use actual observed span (min_bucket → now) for accurate burst rates.
            # Falling back to 1.0s minimum avoids division by zero on single-bucket data.
            if recent:
                span = max(1.0, now - min(recent.keys()))
            else:
                span = max(1.0, self.window)
            return (total_pkts / span), (total_bytes / span)


class FlowTable:
    """
    Thread-safe in-memory table for active network flows using Canonical Bidirectional Session Keys.
    Uses O(1) OrderedDict for LRU operations and bounded active flow analysis.
    """
    def __init__(self, flow_timeout=10.0, max_active_flows=10000, max_flow_duration=60.0, teardown_grace_period=1.0, active_timeout=2.0):
        self.flow_timeout = float(flow_timeout)
        self.max_active_flows = int(max_active_flows)
        self.max_flow_duration = float(max_flow_duration)
        self.teardown_grace_period = float(teardown_grace_period)
        self.active_timeout = float(active_timeout)
        self.flows = OrderedDict()
        self.evicted_buffer = []  # Bounded FIFO for flows evicted due to table capacity limits
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
        
        # Record behavioral telemetry with tcp_flags (O(1))
        self.behavioral.record_packet(src_ip, dst_ip, proto, dst_port, pkt_len, pkt_time, tcp_flags)

        with self.lock:
            if canonical_key in self.flows:
                flow = self.flows[canonical_key]
                self.flows.move_to_end(canonical_key)
            else:
                if len(self.flows) >= self.max_active_flows:
                    # O(1) LRU eviction! Pop oldest flow from the front of OrderedDict
                    oldest_key, oldest_flow = self.flows.popitem(last=False)
                    # Buffer for analysis rather than silently dropping
                    if len(self.evicted_buffer) < 500:
                        self.evicted_buffer.append((oldest_key, oldest_flow, pkt_time))

                flow = FlowRecord(src_ip, dst_ip, proto, src_port, dst_port, start_time=pkt_time)
                self.flows[canonical_key] = flow

            flow.add_packet(src_ip, dst_ip, src_port, dst_port, pkt_len, pkt_time, tcp_flags)

    def _attach_behavioral_context(self, features, current_time):
        features['context_ports_probed'] = self.behavioral.get_port_scan_count(features['source_ip'], features['destination_ip'], current_time)
        features['context_auth_attempts'] = self.behavioral.get_auth_attempt_count(features['source_ip'], features['destination_port'], current_time)
        tgt_pps, tgt_bps = self.behavioral.get_target_traffic_rate(features['destination_ip'], current_time)
        features['context_target_pps'] = tgt_pps
        features['context_target_bps'] = tgt_bps

    def get_expired_flows(self, current_time=None, max_active_batch=50):
        """
        Extracts expired flows (removed from table), capacity-evicted flows,
        AND a controlled bounded batch of active flows eligible for early analysis.
        Preserves the 10.0-second inactivity timeout for normal flow lifecycle.
        """
        if current_time is None:
            current_time = time.time()

        actionable_list = []
        active_analyzed_count = 0

        with self.lock:
            # 1. Drain capacity-evicted flows (avoids silent loss during flood bursts)
            while self.evicted_buffer and len(actionable_list) < 50:
                ev_key, ev_flow, ev_time = self.evicted_buffer.pop(0)
                features = ev_flow.calculate_features(current_time=ev_time)
                features['rate_status'] = "CAPACITY_EVICTED"
                self._attach_behavioral_context(features, current_time)
                actionable_list.append(features)

            # 2. Inspect active flows for expiration and early-analysis eligibility
            keys_to_remove = []
            for key, flow in self.flows.items():
                idle_time = current_time - flow.last_seen
                duration = current_time - flow.start_time
                time_since_eval = current_time - flow.last_analyzed_time
                
                # Check teardown grace expiration
                teardown_expired = False
                if flow.teardown_time is not None:
                    if (current_time - flow.teardown_time) >= self.teardown_grace_period:
                        teardown_expired = True

                # Flow is finalized/expired if idle for >= flow_timeout (10s), or torn down, or duration >= 60s
                is_expired = (idle_time >= self.flow_timeout or teardown_expired or duration >= self.max_flow_duration)
                
                # Early active flow analysis conditions (Task 3, 4, 5):
                is_active_eligible = False
                if not is_expired and active_analyzed_count < max_active_batch:
                    # Criterion B: SYN-only flood check — never-analyzed flows bypass the cooldown.
                    # The 2.0s cooldown is meant to throttle RE-analysis of multi-packet flows,
                    # not to delay the first-ever analysis of brand-new 1-packet SYN probes.
                    if flow.is_syn_only and flow.analysis_count == 0 and (current_time - flow.start_time) >= 1.0:
                        tgt_pps, _ = self.behavioral.get_target_traffic_rate(flow.responder_ip, current_time)
                        if tgt_pps >= 300.0:
                            is_active_eligible = True

                    # Criterion A / re-analysis: Enforce 2.0s cooldown for already-analyzed flows
                    if not is_active_eligible and time_since_eval >= self.active_timeout:
                        pkts_since_eval = flow.packet_count - flow.last_analyzed_pkts

                        # Criterion A: Multi-packet volumetric progress
                        if pkts_since_eval >= 20 or flow.packet_count >= 30:
                            is_active_eligible = True

                        # Criterion B re-check: ongoing SYN flood (already analyzed at least once)
                        elif flow.is_syn_only and (current_time - flow.start_time) >= 1.0:
                            tgt_pps, _ = self.behavioral.get_target_traffic_rate(flow.responder_ip, current_time)
                            if tgt_pps >= 300.0:
                                is_active_eligible = True

                if is_expired:
                    features = flow.calculate_features(current_time=current_time)
                    self._attach_behavioral_context(features, current_time)
                    actionable_list.append(features)
                    keys_to_remove.append(key)
                elif is_active_eligible:
                    features = flow.calculate_features(current_time=current_time)
                    features['rate_status'] = "ACTIVE_SNAPSHOT"
                    flow.last_analyzed_time = current_time
                    flow.last_analyzed_pkts = flow.packet_count
                    flow.analysis_count += 1
                    flow.is_analyzed_active = True
                    self._attach_behavioral_context(features, current_time)
                    actionable_list.append(features)
                    active_analyzed_count += 1

            for key in keys_to_remove:
                del self.flows[key]

        return actionable_list

    def flush_all_flows(self):
        flushed = []
        now = time.time()
        with self.lock:
            while self.evicted_buffer:
                ev_key, ev_flow, ev_time = self.evicted_buffer.pop(0)
                f = ev_flow.calculate_features(current_time=ev_time)
                self._attach_behavioral_context(f, now)
                flushed.append(f)

            for flow in self.flows.values():
                f = flow.calculate_features(current_time=now)
                self._attach_behavioral_context(f, now)
                flushed.append(f)
            self.flows.clear()
        return flushed

    def get_active_flow_count(self):
        with self.lock:
            return len(self.flows)
