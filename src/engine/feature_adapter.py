import pandas as pd
import numpy as np

class FeatureCompatibilityAdapter:
    """
    Adapter bridging real-time 11 network flow features to the UNSW-NB15
    feature representation expected by the trained Machine Learning models.
    """
    @staticmethod
    def adapt_to_model_features(flow_dict):
        """
        Converts an 11-feature flow dictionary into the format required by the Preprocessor.
        """
        duration = max(1e-5, float(flow_dict.get('flow_duration', 0.01)))
        pkt_count = max(1, int(flow_dict.get('packet_count', 1)))
        total_size = float(flow_dict.get('total_flow_size', 1000.0))
        pps = float(flow_dict.get('packets_per_second', pkt_count / duration))
        bps = float(flow_dict.get('bytes_per_second', total_size / duration))
        avg_size = float(flow_dict.get('average_packet_size', total_size / pkt_count))
        std_size = float(flow_dict.get('std_packet_size', 0.0))
        avg_iat = float(flow_dict.get('average_inter_arrival_time', 0.0))
        max_iat = float(flow_dict.get('maximum_inter_arrival_time', 0.0))

        # Build feature vector compatible with UNSW-NB15 scaling columns
        adapted_row = {
            'dur': duration,
            'spkts': pkt_count,
            'dpkts': max(0, int(pkt_count // 2)),
            'sbytes': total_size,
            'dbytes': max(0.0, total_size * 0.4),
            'rate': pps,
            'sttl': 64 if flow_dict.get('protocol') == 'TCP' else 128,
            'dttl': 64,
            'sload': bps * 8.0,  # bits per second
            'dload': bps * 4.0,
            'sloss': 0,
            'dloss': 0,
            'sinpkt': avg_iat * 1000.0,  # ms
            'dinpkt': max_iat * 1000.0,  # ms
            'sjit': std_size,
            'djit': std_size * 0.5,
            'swin': 255 if flow_dict.get('protocol') == 'TCP' else 0,
            'stcpb': 1000000 if flow_dict.get('protocol') == 'TCP' else 0,
            'dtcpb': 1000000 if flow_dict.get('protocol') == 'TCP' else 0,
            'dwin': 255 if flow_dict.get('protocol') == 'TCP' else 0,
            'tcprtt': avg_iat,
            'synack': avg_iat * 0.5,
            'ackdat': avg_iat * 0.5,
            'smean': avg_size,
            'dmean': avg_size * 0.8
        }

        return pd.DataFrame([adapted_row])
