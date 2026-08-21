import os
from scapy.all import rdpcap, IP, TCP, UDP, Ether
import pandas as pd

class DataCollector:
    """
    Module to read PCAP files and extract raw packet information.
    """
    def __init__(self, pcap_path=None):
        self.pcap_path = pcap_path

    def read_pcap(self, path=None):
        """
        Reads a PCAP file and returns a list of packets.
        """
        path = path or self.pcap_path
        if not path or not os.path.exists(path):
            print(f"Error: PCAP file not found at {path}")
            return []
        
        print(f"Reading PCAP file: {path}...")
        try:
            packets = rdpcap(path)
            return packets
        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return []

    def extract_packet_data(self, packets):
        """
        Extracts basic fields from packets into a structured list of dictionaries.
        """
        data = []
        for packet in packets:
            if IP in packet:
                pkt_info = {
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'proto': packet[IP].proto,
                    'size': len(packet),
                    'time': float(packet.time)
                }
                
                if TCP in packet:
                    pkt_info['src_port'] = packet[TCP].sport
                    pkt_info['dst_port'] = packet[TCP].dport
                    pkt_info['type'] = 'TCP'
                elif UDP in packet:
                    pkt_info['src_port'] = packet[UDP].sport
                    pkt_info['dst_port'] = packet[UDP].dport
                    pkt_info['type'] = 'UDP'
                else:
                    pkt_info['src_port'] = 0
                    pkt_info['dst_port'] = 0
                    pkt_info['type'] = 'Other'
                
                data.append(pkt_info)
        
        return pd.DataFrame(data)

if __name__ == "__main__":
    # Test with a dummy path or if a pcap exists
    collector = DataCollector("data/sample.pcap")
    df = collector.extract_packet_data(collector.read_pcap())
    if not df.empty:
        print(df.head())
        df.to_csv("data/raw_traffic.csv", index=False)
        print("Raw traffic data saved to data/raw_traffic.csv")
