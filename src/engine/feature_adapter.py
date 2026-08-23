import pandas as pd
import numpy as np

class FeatureCompatibilityAdapter:
    """
    Adapter extracting and formatting the standard 11 network flow features
    for the Preprocessor and Machine Learning models.
    """
    @staticmethod
    def adapt_to_model_features(flow_dict):
        """
        Converts an 11-feature flow dictionary into the format required by the Preprocessor.
        """
        duration = max(1e-5, float(flow_dict.get('flow_duration', 0.01)))
        pkt_count = max(1, int(flow_dict.get('packet_count', 1)))
        total_size = max(0.0, float(flow_dict.get('total_flow_size', 0.0)))
        
        pps = float(flow_dict.get('packets_per_second', pkt_count / duration))
        bps = float(flow_dict.get('bytes_per_second', total_size / duration))
        avg_size = float(flow_dict.get('average_packet_size', total_size / pkt_count))
        std_size = max(0.0, float(flow_dict.get('std_packet_size', 0.0)))
        avg_iat = max(0.0, float(flow_dict.get('average_inter_arrival_time', 0.0)))
        max_iat = max(0.0, float(flow_dict.get('maximum_inter_arrival_time', 0.0)))

        # Build feature vector matching FLOW_NUMERIC_FEATURES exactly
        adapted_row = {
            'total_flow_size': total_size,
            'average_packet_size': avg_size,
            'std_packet_size': std_size,
            'packet_count': pkt_count,
            'flow_duration': duration,
            'average_inter_arrival_time': avg_iat,
            'maximum_inter_arrival_time': max_iat,
            'packets_per_second': pps,
            'bytes_per_second': bps
        }

        return pd.DataFrame([adapted_row])
