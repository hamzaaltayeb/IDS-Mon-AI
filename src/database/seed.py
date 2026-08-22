import os
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from .connection import get_db

def seed_initial_data():
    with get_db() as conn:
        cur = conn.cursor()
        
        # 1. Seed Users if table is empty
        cur.execute('SELECT COUNT(*) FROM users')
        user_count = cur.fetchone()[0]
        
        if user_count == 0:
            print("Seeding initial administrator and security analyst accounts...")
            admin_hash = generate_password_hash('Admin@12345')
            analyst_hash = generate_password_hash('Analyst@12345')
            now = datetime.now().isoformat()
            
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role, is_active, must_change_password, created_at)
                VALUES 
                ('admin', 'admin@ids.local', ?, 'ADMIN', 1, 1, ?),
                ('analyst', 'analyst@ids.local', ?, 'SECURITY_ANALYST', 1, 1, ?)
            """, (admin_hash, now, analyst_hash, now))

            # Initial audit logs
            cur.execute("""
                INSERT INTO system_logs (user_id, action, description, ip_address, created_at)
                VALUES 
                (1, 'SYSTEM_INIT', 'Initial operational database and security tables created', '127.0.0.1', ?),
                (1, 'USER_SEED', 'Default Administrator account created', '127.0.0.1', ?),
                (2, 'USER_SEED', 'Default Security Analyst account created', '127.0.0.1', ?)
            """, (now, now, now))

        # 2. Seed initial demo flows only if explicitly requested via INITIAL_DEMO_SEED env var
        cur.execute('SELECT COUNT(*) FROM network_flows')
        flow_count = cur.fetchone()[0]
        
        if flow_count == 0 and os.environ.get('INITIAL_DEMO_SEED', '0') == '1':
            print("Seeding initial security events for SOC Dashboard...")
            sample_events = [
                ('192.168.1.105', '10.0.0.1', 'TCP', 80, 0.45, 185000.0, 1420.0, 110.0, 1300, 0.0003, 0.001, 2888.8, 411111.1, 'ATTACK', 'DDOS', 0.98, 95, 'CRITICAL', 'Volumetric flood signature; packet rate > 2500 pkt/s; high byte volume on port 80', 'DDoS Attack Flood Detected', 'Heavy HTTP flood targeting web server on port 80 from 192.168.1.105'),
                ('192.168.1.142', '10.0.0.1', 'TCP', 22, 12.5, 4200.0, 180.0, 35.0, 115, 0.108, 0.45, 9.2, 336.0, 'ATTACK', 'BRUTE_FORCE', 0.92, 85, 'HIGH', 'Repetitive authentication attempts on SSH port 22 with fixed intervals', 'SSH Brute Force Attempt', 'Repeated failed credential attempts detected on port 22 from 192.168.1.142'),
                ('192.168.1.201', '10.0.0.1', 'TCP', 445, 0.05, 120.0, 40.0, 0.0, 3, 0.015, 0.025, 60.0, 2400.0, 'ATTACK', 'PORT_SCAN', 0.88, 70, 'HIGH', 'Rapid SYN sweep across multiple ports with small fixed packet size', 'Port Scan Reconnaissance', 'Reconnaissance port scan targeting service ports from 192.168.1.201'),
                ('192.168.1.88', '10.0.0.1', 'UDP', 53, 1.2, 850.0, 140.0, 20.0, 6, 0.20, 0.40, 5.0, 708.3, 'NORMAL', 'NORMAL', 0.99, 0, 'LOW', 'Standard recursive DNS lookup pattern', None, None),
                ('192.168.1.177', '10.0.0.1', 'TCP', 443, 8.4, 65400.0, 520.0, 140.0, 125, 0.067, 0.32, 14.8, 7785.7, 'NORMAL', 'NORMAL', 0.96, 0, 'LOW', 'Standard TLS encrypted web traffic', None, None),
                ('192.168.1.220', '10.0.0.1', 'TCP', 8080, 0.85, 3400.0, 850.0, 210.0, 4, 0.21, 0.50, 4.7, 4000.0, 'ATTACK', 'UNKNOWN', 0.74, 50, 'MEDIUM', 'Statistical anomaly flagged by Isolation Forest; atypical packet-to-byte ratio', 'Suspicious Traffic Anomaly', 'Unsupervised anomaly detector identified unusual flow pattern from 192.168.1.220'),
                ('192.168.1.109', '10.0.0.1', 'TCP', 80, 0.35, 210000.0, 1450.0, 95.0, 1450, 0.0002, 0.0008, 4142.8, 600000.0, 'ATTACK', 'DDOS', 0.99, 95, 'CRITICAL', 'Volumetric flood signature; rate > 4000 pkt/s', 'Critical DDoS Flood Detected', 'Massive HTTP flood detected from 192.168.1.109'),
                ('192.168.1.134', '10.0.0.1', 'TCP', 21, 18.0, 5800.0, 210.0, 40.0, 140, 0.128, 0.60, 7.7, 322.2, 'ATTACK', 'BRUTE_FORCE', 0.89, 85, 'HIGH', 'FTP dictionary attack signature on port 21', 'FTP Brute Force Attempt', 'Multiple authentication attempts on FTP server from 192.168.1.134'),
                ('192.168.1.215', '10.0.0.1', 'TCP', 3389, 0.02, 80.0, 40.0, 0.0, 2, 0.01, 0.01, 100.0, 4000.0, 'ATTACK', 'PORT_SCAN', 0.85, 70, 'HIGH', 'RDP port probing detected', 'RDP Reconnaissance Scan', 'Port scan probing RDP port from 192.168.1.215'),
                ('192.168.1.45', '10.0.0.1', 'TCP', 443, 4.2, 32000.0, 400.0, 110.0, 80, 0.052, 0.25, 19.0, 7619.0, 'NORMAL', 'NORMAL', 0.97, 0, 'LOW', 'Legitimate HTTPS browsing session', None, None)
            ]

            base_time = datetime.now() - timedelta(minutes=45)
            for i, ev in enumerate(sample_events):
                ev_time = (base_time + timedelta(minutes=i*4)).isoformat()
                
                # Flow
                cur.execute("""
                    INSERT INTO network_flows (
                        source_ip, destination_ip, protocol, destination_port,
                        flow_duration, total_flow_size, average_packet_size, std_packet_size,
                        packet_count, average_inter_arrival_time, maximum_inter_arrival_time,
                        packets_per_second, bytes_per_second, captured_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ev[0], ev[1], ev[2], ev[3], ev[4], ev[5], ev[6], ev[7], ev[8], ev[9], ev[10], ev[11], ev[12], ev_time))
                flow_id = cur.lastrowid
                
                # Detection
                cur.execute("""
                    INSERT INTO detections (flow_id, prediction, attack_type, confidence, threat_score, severity, indicators, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (flow_id, ev[13], ev[14], ev[15], ev[16], ev[17], ev[18], ev_time))
                det_id = cur.lastrowid
                
                # Alert if suspicious
                if ev[16] > 0 and ev[19] is not None:
                    cur.execute("""
                        INSERT INTO alerts (detection_id, title, message, severity, status, created_at)
                        VALUES (?, ?, ?, ?, 'NEW', ?)
                    """, (det_id, ev[19], ev[20], ev[17], ev_time))
