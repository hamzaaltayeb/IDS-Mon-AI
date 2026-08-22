import os
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class FeatureExtractor:
    """
    Module to transform raw packet data into network flow features.
    """
    def __init__(self):
        pass

    def extract_features(self, df):
        """
        Groups packet data into flows and calculates summary statistics.
        """
        if df.empty:
            return pd.DataFrame()

        working_df = df.copy()
        
        # Sort packets chronologically by time if time column exists
        if 'time' in working_df.columns:
            working_df = working_df.sort_values(by='time')

        # Calculate time diff between consecutive packets in the same flow
        working_df['time_diff'] = working_df.groupby(['src_ip', 'dst_ip', 'proto', 'dst_port'])['time'].diff().fillna(0)
        
        # Aggregate features
        flow_features = working_df.groupby(['src_ip', 'dst_ip', 'proto', 'dst_port']).agg({
            'size': ['sum', 'mean', 'std', 'count'],
            'time_diff': ['sum', 'mean', 'max']
        }).reset_index()

        # Flatten multi-index columns
        flow_features.columns = [
            'src_ip', 'dst_ip', 'proto', 'dst_port', 
            'total_size', 'avg_size', 'std_size', 'pkt_count',
            'duration', 'avg_inter_arrival', 'max_inter_arrival'
        ]

        # Fill NaNs from std deviation
        flow_features = flow_features.fillna(0)
        
        # Additional engineered features
        flow_features['packets_per_second'] = flow_features['pkt_count'] / (flow_features['duration'] + 1e-6)
        flow_features['bytes_per_second'] = flow_features['total_size'] / (flow_features['duration'] + 1e-6)

        return flow_features

if __name__ == "__main__":
    # Example usage
    raw_traffic_file = os.path.join(BASE_DIR, "data", "raw_traffic.csv")
    out_features_file = os.path.join(BASE_DIR, "data", "flow_features.csv")
    try:
        raw_df = pd.read_csv(raw_traffic_file)
        extractor = FeatureExtractor()
        features = extractor.extract_features(raw_df)
        print(features.head())
        os.makedirs(os.path.dirname(out_features_file), exist_ok=True)
        features.to_csv(out_features_file, index=False)
        print(f"Flow features saved to {out_features_file}")
    except FileNotFoundError:
        print(f"Please run data_collector.py first to generate {raw_traffic_file}")

