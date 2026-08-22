import time
import math
import threading
import numpy as np

class FlowRecord:
    """
    Maintains state and statistics for a single network flow session.
    """
    def __init__(self, src_ip, dst_ip, proto, dst_port, src_port=0, start_time=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.dst_port = dst_port
        self.src_port = src_port
        
        self.start_time = start_time if start_time is not None else time.time()
        self.last_seen = self.start_time
        
        self.packet_count = 0
        self.total_bytes = 0
        self.packet_lengths = []
        self.arrival_times = []
        self.is_terminated = False

    def add_packet(self, pkt_len, pkt_time=None, tcp_flags=None):
        if pkt_time is None:
            pkt_time = time.time()
            
        self.last_seen = pkt_time
        self.packet_count += 1
        self.total_bytes += pkt_len
        self.packet_lengths.append(pkt_len)
        self.arrival_times.append(pkt_time)

        # Check TCP session termination (FIN: 0x01, RST: 0x04)
        if tcp_flags is not None:
            if tcp_flags & 0x01 or tcp_flags & 0x04:
                self.is_terminated = True

    def calculate_features(self):
        """
        Calculates the 11 standard flow features with strict mathematical safety.
        """
        duration = max(1e-5, self.last_seen - self.start_time)
        pkt_count = max(1, self.packet_count)
        total_size = float(self.total_bytes)
        
        # 1. Average packet size
        avg_size = total_size / pkt_count
        
        # 2. Standard deviation of packet size
        if len(self.packet_lengths) > 1:
            std_size = float(np.std(self.packet_lengths))
        else:
            std_size = 0.0
            
        # 3. Inter-arrival times
        if len(self.arrival_times) > 1:
            iats = np.diff(self.arrival_times)
            avg_iat = float(np.mean(iats))
            max_iat = float(np.max(iats))
        else:
            avg_iat = 0.0
            max_iat = 0.0
            
        # 4. Rates
        pps = float(pkt_count / duration)
        bps = float(total_size / duration)

        return {
            'source_ip': self.src_ip,
            'destination_ip': self.dst_ip,
            'protocol': self.proto,
            'destination_port': int(self.dst_port),
            'flow_duration': round(duration, 4),
            'total_flow_size': round(total_size, 2),
            'average_packet_size': round(avg_size, 2),
            'std_packet_size': round(std_size, 2),
            'packet_count': int(pkt_count),
            'average_inter_arrival_time': round(avg_iat, 5),
            'maximum_inter_arrival_time': round(max_iat, 5),
            'packets_per_second': round(pps, 2),
            'bytes_per_second': round(bps, 2)
        }


class FlowTable:
    """
    Thread-safe in-memory table for active network flows with automatic expiration.
    """
    def __init__(self, flow_timeout=10.0, max_active_flows=10000, max_flow_duration=60.0):
        self.flow_timeout = float(flow_timeout)
        self.max_active_flows = int(max_active_flows)
        self.max_flow_duration = float(max_flow_duration)
        self.flows = {}
        self.lock = threading.Lock()

    def _get_key(self, src_ip, dst_ip, proto, dst_port, src_port):
        # 5-tuple key
        return (src_ip, dst_ip, proto, dst_port, src_port)

    def process_packet(self, src_ip, dst_ip, proto, dst_port, src_port, pkt_len, pkt_time=None, tcp_flags=None):
        if pkt_time is None:
            pkt_time = time.time()

        key = self._get_key(src_ip, dst_ip, proto, dst_port, src_port)
        
        with self.lock:
            if key not in self.flows:
                # Evict oldest flow if table exceeds max capacity
                if len(self.flows) >= self.max_active_flows:
                    oldest_key = min(self.flows.keys(), key=lambda k: self.flows[k].last_seen)
                    del self.flows[oldest_key]

                self.flows[key] = FlowRecord(src_ip, dst_ip, proto, dst_port, src_port, start_time=pkt_time)

            flow = self.flows[key]
            flow.add_packet(pkt_len, pkt_time, tcp_flags)

    def get_expired_flows(self, current_time=None):
        """
        Extracts and removes expired or terminated flows from the table.
        """
        if current_time is None:
            current_time = time.time()

        expired_list = []
        with self.lock:
            keys_to_remove = []
            for key, flow in self.flows.items():
                idle_time = current_time - flow.last_seen
                duration = current_time - flow.start_time
                
                # Expiration conditions:
                # 1. Idle time exceeds timeout
                # 2. TCP connection terminated (FIN/RST)
                # 3. Maximum active session duration exceeded
                if idle_time >= self.flow_timeout or flow.is_terminated or duration >= self.max_flow_duration:
                    expired_list.append(flow.calculate_features())
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.flows[key]

        return expired_list

    def flush_all_flows(self):
        """
        Flushes all active flows immediately (used during graceful shutdown).
        """
        flushed = []
        with self.lock:
            for flow in self.flows.values():
                flushed.append(flow.calculate_features())
            self.flows.clear()
        return flushed

    def get_active_flow_count(self):
        with self.lock:
            return len(self.flows)
