import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from .connection import get_db

class User:
    def __init__(self, id=None, username='', email='', password_hash='', role='SECURITY_ANALYST', is_active=1, must_change_password=0, created_at=None, last_login=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.is_active = bool(is_active)
        self.must_change_password = bool(must_change_password)
        self.created_at = created_at or datetime.now().isoformat()
        self.last_login = last_login

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'must_change_password': self.must_change_password,
            'created_at': self.created_at,
            'last_login': self.last_login
        }

    @staticmethod
    def from_row(row):
        if not row:
            return None
        return User(
            id=row['id'],
            username=row['username'],
            email=row['email'],
            password_hash=row['password_hash'],
            role=row['role'],
            is_active=row['is_active'],
            must_change_password=row['must_change_password'],
            created_at=row['created_at'],
            last_login=row['last_login']
        )

    @classmethod
    def find_by_username_or_email(cls, identifier):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE (username = ? OR email = ?) LIMIT 1', (identifier, identifier))
            return cls.from_row(cur.fetchone())

    @classmethod
    def find_by_id(cls, user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = ? LIMIT 1', (user_id,))
            return cls.from_row(cur.fetchone())

    @classmethod
    def get_all(cls):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users ORDER BY id ASC')
            return [cls.from_row(r) for r in cur.fetchall()]

    @classmethod
    def create(cls, username, email, password, role='SECURITY_ANALYST', must_change=False):
        hashed = generate_password_hash(password)
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (username, email, password_hash, role, is_active, must_change_password, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)',
                (username, email, hashed, role, 1 if must_change else 0, now)
            )
            return cur.lastrowid

    @classmethod
    def update_last_login(cls, user_id):
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, user_id))

    @classmethod
    def update_password(cls, user_id, new_password):
        hashed = generate_password_hash(new_password)
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?', (hashed, user_id))

    @classmethod
    def toggle_active(cls, user_id, is_active):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET is_active = ? WHERE id = ?', (1 if is_active else 0, user_id))

    @classmethod
    def update_role(cls, user_id, new_role):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))

    @classmethod
    def delete(cls, user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM users WHERE id = ?', (user_id,))


class NetworkFlow:
    def __init__(self, id=None, source_ip='', destination_ip='', protocol='TCP', destination_port=80, flow_duration=0.0,
                 total_flow_size=0.0, average_packet_size=0.0, std_packet_size=0.0, packet_count=0,
                 average_inter_arrival_time=0.0, maximum_inter_arrival_time=0.0, packets_per_second=0.0,
                 bytes_per_second=0.0, captured_at=None, traffic_source='live', session_id=''):
        self.id = id
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.destination_port = destination_port
        self.flow_duration = float(flow_duration)
        self.total_flow_size = float(total_flow_size)
        self.average_packet_size = float(average_packet_size)
        self.std_packet_size = float(std_packet_size)
        self.packet_count = int(packet_count)
        self.average_inter_arrival_time = float(average_inter_arrival_time)
        self.maximum_inter_arrival_time = float(maximum_inter_arrival_time)
        self.packets_per_second = float(packets_per_second)
        self.bytes_per_second = float(bytes_per_second)
        self.captured_at = captured_at or datetime.now().isoformat()
        self.traffic_source = traffic_source or 'live'
        self.session_id = session_id or ''

    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'destination_port': self.destination_port,
            'flow_duration': round(self.flow_duration, 4),
            'total_flow_size': self.total_flow_size,
            'average_packet_size': round(self.average_packet_size, 2),
            'std_packet_size': round(self.std_packet_size, 2),
            'packet_count': self.packet_count,
            'average_inter_arrival_time': round(self.average_inter_arrival_time, 5),
            'maximum_inter_arrival_time': round(self.maximum_inter_arrival_time, 5),
            'packets_per_second': round(self.packets_per_second, 2),
            'bytes_per_second': round(self.bytes_per_second, 2),
            'captured_at': self.captured_at,
            'traffic_source': self.traffic_source,
            'session_id': self.session_id
        }

    @staticmethod
    def from_row(row):
        if not row: return None
        keys = row.keys() if hasattr(row, 'keys') else []
        return NetworkFlow(
            id=row['id'],
            source_ip=row['source_ip'],
            destination_ip=row['destination_ip'],
            protocol=row['protocol'],
            destination_port=row['destination_port'],
            flow_duration=row['flow_duration'],
            total_flow_size=row['total_flow_size'],
            average_packet_size=row['average_packet_size'],
            std_packet_size=row['std_packet_size'],
            packet_count=row['packet_count'],
            average_inter_arrival_time=row['average_inter_arrival_time'],
            maximum_inter_arrival_time=row['maximum_inter_arrival_time'],
            packets_per_second=row['packets_per_second'],
            bytes_per_second=row['bytes_per_second'],
            captured_at=row['captured_at'],
            traffic_source=row['traffic_source'] if 'traffic_source' in keys else 'live',
            session_id=row['session_id'] if 'session_id' in keys else ''
        )

    @classmethod
    def create(cls, flow_data):
        now = flow_data.get('captured_at') or datetime.now().isoformat()
        traffic_source = flow_data.get('traffic_source', 'live')
        session_id = flow_data.get('session_id', '')
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO network_flows (
                    source_ip, destination_ip, protocol, destination_port,
                    flow_duration, total_flow_size, average_packet_size, std_packet_size,
                    packet_count, average_inter_arrival_time, maximum_inter_arrival_time,
                    packets_per_second, bytes_per_second, captured_at, traffic_source, session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow_data.get('source_ip', '127.0.0.1'),
                flow_data.get('destination_ip', '192.168.1.1'),
                str(flow_data.get('protocol', 'TCP')),
                int(flow_data.get('destination_port', 80)),
                float(flow_data.get('flow_duration', 0.0)),
                float(flow_data.get('total_flow_size', 0.0)),
                float(flow_data.get('average_packet_size', 0.0)),
                float(flow_data.get('std_packet_size', 0.0)),
                int(flow_data.get('packet_count', 0)),
                float(flow_data.get('average_inter_arrival_time', 0.0)),
                float(flow_data.get('maximum_inter_arrival_time', 0.0)),
                float(flow_data.get('packets_per_second', 0.0)),
                float(flow_data.get('bytes_per_second', 0.0)),
                now,
                traffic_source,
                session_id
            ))
            return cur.lastrowid

    @classmethod
    def get_all(cls, limit=100, offset=0, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = 'SELECT * FROM network_flows WHERE 1=1'
            params = []
            if traffic_source and traffic_source != 'ALL':
                query += ' AND traffic_source = ?'
                params.append(traffic_source)
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            cur.execute(query, tuple(params))
            return [cls.from_row(r) for r in cur.fetchall()]

    @classmethod
    def count(cls, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = 'SELECT COUNT(*) FROM network_flows WHERE 1=1'
            params = []
            if traffic_source and traffic_source != 'ALL':
                query += ' AND traffic_source = ?'
                params.append(traffic_source)
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            cur.execute(query, tuple(params))
            return cur.fetchone()[0]


class Detection:
    def __init__(self, id=None, flow_id=None, prediction='NORMAL', attack_type='NORMAL', confidence=1.0,
                 threat_score=0, severity='LOW', indicators='', detected_at=None, traffic_source='live', session_id=''):
        self.id = id
        self.flow_id = flow_id
        self.prediction = prediction
        self.attack_type = attack_type
        self.confidence = float(confidence)
        self.threat_score = int(threat_score)
        self.severity = severity
        self.indicators = indicators or ''
        self.detected_at = detected_at or datetime.now().isoformat()
        self.traffic_source = traffic_source or 'live'
        self.session_id = session_id or ''

    def to_dict(self):
        return {
            'id': self.id,
            'flow_id': self.flow_id,
            'prediction': self.prediction,
            'attack_type': self.attack_type,
            'confidence': round(self.confidence, 4),
            'threat_score': self.threat_score,
            'severity': self.severity,
            'indicators': self.indicators,
            'detected_at': self.detected_at,
            'traffic_source': self.traffic_source,
            'session_id': self.session_id
        }

    @staticmethod
    def from_row(row):
        if not row: return None
        keys = row.keys() if hasattr(row, 'keys') else []
        return Detection(
            id=row['id'],
            flow_id=row['flow_id'],
            prediction=row['prediction'],
            attack_type=row['attack_type'],
            confidence=row['confidence'],
            threat_score=row['threat_score'],
            severity=row['severity'],
            indicators=row['indicators'],
            detected_at=row['detected_at'],
            traffic_source=row['traffic_source'] if 'traffic_source' in keys else 'live',
            session_id=row['session_id'] if 'session_id' in keys else ''
        )

    @classmethod
    def create(cls, flow_id, prediction, attack_type, confidence, threat_score, severity, indicators='', traffic_source='live', session_id=''):
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO detections (flow_id, prediction, attack_type, confidence, threat_score, severity, indicators, detected_at, traffic_source, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (flow_id, prediction, attack_type, float(confidence), int(threat_score), severity, indicators, now, traffic_source, session_id))
            return cur.lastrowid

    @classmethod
    def get_all(cls, limit=50, offset=0, attack_type=None, severity=None, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = """
                SELECT d.*, f.source_ip, f.destination_ip, f.protocol, f.destination_port, f.packets_per_second, f.bytes_per_second, f.traffic_source as flow_source
                FROM detections d
                JOIN network_flows f ON d.flow_id = f.id
                WHERE 1=1
            """
            params = []
            if attack_type and attack_type != 'ALL':
                query += ' AND d.attack_type = ?'
                params.append(attack_type)
            if severity and severity != 'ALL':
                query += ' AND d.severity = ?'
                params.append(severity)
            if traffic_source and traffic_source != 'ALL':
                query += ' AND (d.traffic_source = ? OR f.traffic_source = ?)'
                params.extend([traffic_source, traffic_source])
            if session_id:
                query += ' AND d.session_id = ?'
                params.append(session_id)
            query += ' ORDER BY d.id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            cur.execute(query, tuple(params))
            results = []
            for r in cur.fetchall():
                d = cls.from_row(r).to_dict()
                d['source_ip'] = r['source_ip']
                d['destination_ip'] = r['destination_ip']
                d['protocol'] = r['protocol']
                d['destination_port'] = r['destination_port']
                d['packets_per_second'] = r['packets_per_second']
                d['bytes_per_second'] = r['bytes_per_second']
                d['traffic_source'] = r['traffic_source'] if 'traffic_source' in r.keys() else 'live'
                results.append(d)
            return results

    @classmethod
    def find_by_id_with_flow(cls, detection_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT d.*, f.source_ip, f.destination_ip, f.protocol, f.destination_port,
                       f.flow_duration, f.total_flow_size, f.average_packet_size, f.std_packet_size,
                       f.packet_count, f.average_inter_arrival_time, f.maximum_inter_arrival_time,
                       f.packets_per_second, f.bytes_per_second, f.captured_at, f.traffic_source as flow_source
                FROM detections d
                JOIN network_flows f ON d.flow_id = f.id
                WHERE d.id = ? LIMIT 1
            """, (detection_id,))
            r = cur.fetchone()
            if not r: return None
            data = cls.from_row(r).to_dict()
            data['flow'] = {
                'id': r['flow_id'],
                'source_ip': r['source_ip'],
                'destination_ip': r['destination_ip'],
                'protocol': r['protocol'],
                'destination_port': r['destination_port'],
                'flow_duration': r['flow_duration'],
                'total_flow_size': r['total_flow_size'],
                'average_packet_size': r['average_packet_size'],
                'std_packet_size': r['std_packet_size'],
                'packet_count': r['packet_count'],
                'average_inter_arrival_time': r['average_inter_arrival_time'],
                'maximum_inter_arrival_time': r['maximum_inter_arrival_time'],
                'packets_per_second': r['packets_per_second'],
                'bytes_per_second': r['bytes_per_second'],
                'captured_at': r['captured_at'],
                'traffic_source': r['flow_source']
            }
            return data

    @classmethod
    def count(cls, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = 'SELECT COUNT(*) FROM detections WHERE 1=1'
            params = []
            if traffic_source and traffic_source != 'ALL':
                query += ' AND traffic_source = ?'
                params.append(traffic_source)
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            cur.execute(query, tuple(params))
            return cur.fetchone()[0]


class Alert:
    def __init__(self, id=None, detection_id=None, title='', message='', severity='LOW', status='NEW',
                 created_at=None, acknowledged_at=None, resolved_at=None):
        self.id = id
        self.detection_id = detection_id
        self.title = title
        self.message = message
        self.severity = severity
        self.status = status
        self.created_at = created_at or datetime.now().isoformat()
        self.acknowledged_at = acknowledged_at
        self.resolved_at = resolved_at

    def to_dict(self):
        return {
            'id': self.id,
            'detection_id': self.detection_id,
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'status': self.status,
            'created_at': self.created_at,
            'acknowledged_at': self.acknowledged_at,
            'resolved_at': self.resolved_at
        }

    @staticmethod
    def from_row(row):
        if not row: return None
        return Alert(
            id=row['id'],
            detection_id=row['detection_id'],
            title=row['title'],
            message=row['message'],
            severity=row['severity'],
            status=row['status'],
            created_at=row['created_at'],
            acknowledged_at=row['acknowledged_at'],
            resolved_at=row['resolved_at']
        )

    @classmethod
    def create(cls, detection_id, title, message, severity, status='NEW'):
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO alerts (detection_id, title, message, severity, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (detection_id, title, message, severity, status, now))
            return cur.lastrowid

    @classmethod
    def get_all(cls, limit=50, offset=0, status=None, severity=None, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = """
                SELECT a.*, d.attack_type, d.threat_score, d.confidence, f.source_ip, f.destination_ip, f.traffic_source
                FROM alerts a
                JOIN detections d ON a.detection_id = d.id
                JOIN network_flows f ON d.flow_id = f.id
                WHERE 1=1
            """
            params = []
            if status and status != 'ALL':
                query += ' AND a.status = ?'
                params.append(status)
            if severity and severity != 'ALL':
                query += ' AND a.severity = ?'
                params.append(severity)
            if traffic_source and traffic_source != 'ALL':
                query += ' AND f.traffic_source = ?'
                params.append(traffic_source)
            if session_id:
                query += ' AND d.session_id = ?'
                params.append(session_id)
            query += ' ORDER BY a.id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            cur.execute(query, tuple(params))
            results = []
            for r in cur.fetchall():
                d = cls.from_row(r).to_dict()
                d['attack_type'] = r['attack_type']
                d['threat_score'] = r['threat_score']
                d['confidence'] = r['confidence']
                d['source_ip'] = r['source_ip']
                d['destination_ip'] = r['destination_ip']
                d['traffic_source'] = r['traffic_source']
                results.append(d)
            return results

    @classmethod
    def find_by_id(cls, alert_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM alerts WHERE id = ? LIMIT 1', (alert_id,))
            return cls.from_row(cur.fetchone())

    @classmethod
    def update_status(cls, alert_id, new_status):
        now = datetime.now().isoformat()
        ack_time = now if new_status == 'ACKNOWLEDGED' else None
        res_time = now if new_status == 'RESOLVED' else None
        with get_db() as conn:
            cur = conn.cursor()
            if new_status == 'ACKNOWLEDGED':
                cur.execute('UPDATE alerts SET status = ?, acknowledged_at = ? WHERE id = ?', (new_status, ack_time, alert_id))
            elif new_status == 'RESOLVED':
                cur.execute('UPDATE alerts SET status = ?, resolved_at = ? WHERE id = ?', (new_status, res_time, alert_id))
            else:
                cur.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))

    @classmethod
    def count(cls, status=None, severity=None, traffic_source=None, session_id=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = """
                SELECT COUNT(*) FROM alerts a
                JOIN detections d ON a.detection_id = d.id
                JOIN network_flows f ON d.flow_id = f.id
                WHERE 1=1
            """
            params = []
            if status:
                query += ' AND a.status = ?'
                params.append(status)
            if severity:
                query += ' AND a.severity = ?'
                params.append(severity)
            if traffic_source and traffic_source != 'ALL':
                query += ' AND f.traffic_source = ?'
                params.append(traffic_source)
            if session_id:
                query += ' AND d.session_id = ?'
                params.append(session_id)
            cur.execute(query, tuple(params))
            return cur.fetchone()[0]


class SystemLog:
    def __init__(self, id=None, user_id=None, action='', description='', ip_address='', created_at=None):
        self.id = id
        self.user_id = user_id
        self.action = action
        self.description = description
        self.ip_address = ip_address
        self.created_at = created_at or datetime.now().isoformat()

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'description': self.description,
            'ip_address': self.ip_address,
            'created_at': self.created_at
        }

    @staticmethod
    def from_row(row):
        if not row: return None
        return SystemLog(
            id=row['id'],
            user_id=row['user_id'],
            action=row['action'],
            description=row['description'],
            ip_address=row['ip_address'],
            created_at=row['created_at']
        )

    @classmethod
    def create(cls, user_id, action, description='', ip_address='127.0.0.1'):
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO system_logs (user_id, action, description, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, action, description, ip_address, now))
            return cur.lastrowid

    @classmethod
    def get_all(cls, limit=100, offset=0, user_id=None, action_search=None):
        with get_db() as conn:
            cur = conn.cursor()
            query = """
                SELECT l.*, u.username, u.role
                FROM system_logs l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE 1=1
            """
            params = []
            if user_id:
                query += ' AND l.user_id = ?'
                params.append(user_id)
            if action_search:
                query += ' AND (l.action LIKE ? OR l.description LIKE ?)'
                params.extend([f'%{action_search}%', f'%{action_search}%'])
            query += ' ORDER BY l.id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            cur.execute(query, tuple(params))
            results = []
            for r in cur.fetchall():
                d = cls.from_row(r).to_dict()
                d['username'] = r['username'] or 'SYSTEM'
                d['role'] = r['role'] or 'SYSTEM'
                results.append(d)
            return results
