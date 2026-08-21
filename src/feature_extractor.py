import pandas as pd
import numpy as np

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

        # Group by Source IP, Destination IP, Protocol, and Destination Port (NetFlow style)
        # We also need to define a 'flow' based on time if we want to be more realistic, 
        # but for this project, grouping by these keys is a good start.
        
        # Calculate duration
        df['time_diff'] = df.groupby(['src_ip', 'dst_ip', 'proto', 'dst_port'])['time'].diff().fillna(0)
        
        # Aggregate features
        flow_features = df.groupby(['src_ip', 'dst_ip', 'proto', 'dst_port']).agg({
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
    try:
        raw_df = pd.read_csv("data/raw_traffic.csv")
        extractor = FeatureExtractor()
        features = extractor.extract_features(raw_df)
        print(features.head())
        features.to_csv("data/flow_features.csv", index=False)
        print("Flow features saved to data/flow_features.csv")
    except FileNotFoundError:
        print("Please run data_collector.py first to generate raw_traffic.csv")
