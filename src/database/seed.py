from datetime import datetime
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
