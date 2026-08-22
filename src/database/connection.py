import os
import sqlite3
from datetime import datetime
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_SQLITE_PATH = os.path.join(DATA_DIR, 'ids_database.db')
DATABASE_URL = os.getenv('DATABASE_URL', f'sqlite:///{DEFAULT_SQLITE_PATH}')

class DBConnection:
    _instance = None

    def __init__(self):
        self.is_postgres = DATABASE_URL.startswith('postgresql') or DATABASE_URL.startswith('postgres')
        self.sqlite_path = DEFAULT_SQLITE_PATH

    def get_raw_connection(self):
        if self.is_postgres:
            try:
                import psycopg2
                import psycopg2.extras
                return psycopg2.connect(DATABASE_URL)
            except Exception as e:
                print(f'PostgreSQL connection error: {e}. Falling back to SQLite...')
                self.is_postgres = False
        
        conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

db_mgr = DBConnection()

@contextmanager
def get_db():
    conn = db_mgr.get_raw_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. users
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'SECURITY_ANALYST',
            is_active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
        """)

        # 2. network_flows
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            destination_port INTEGER NOT NULL,
            flow_duration REAL NOT NULL DEFAULT 0.0,
            total_flow_size REAL NOT NULL DEFAULT 0.0,
            average_packet_size REAL NOT NULL DEFAULT 0.0,
            std_packet_size REAL NOT NULL DEFAULT 0.0,
            packet_count INTEGER NOT NULL DEFAULT 0,
            average_inter_arrival_time REAL NOT NULL DEFAULT 0.0,
            maximum_inter_arrival_time REAL NOT NULL DEFAULT 0.0,
            packets_per_second REAL NOT NULL DEFAULT 0.0,
            bytes_per_second REAL NOT NULL DEFAULT 0.0,
            captured_at TEXT NOT NULL
        )
        """)

        # 3. detections
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            threat_score INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL DEFAULT 'LOW',
            indicators TEXT,
            detected_at TEXT NOT NULL,
            FOREIGN KEY (flow_id) REFERENCES network_flows (id) ON DELETE CASCADE
        )
        """)

        # 4. alerts
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            resolved_at TEXT,
            FOREIGN KEY (detection_id) REFERENCES detections (id) ON DELETE CASCADE
        )
        """)

        # 5. system_logs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
        """)

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_captured ON network_flows(captured_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_det_attack ON detections(attack_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_det_severity ON detections(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_created ON system_logs(created_at)")

    # Run seed
    from .seed import seed_initial_data
    seed_initial_data()
    print('Database initialized and indexed successfully.')
