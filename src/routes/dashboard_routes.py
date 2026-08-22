from flask import Blueprint, render_template, jsonify
from database.models import NetworkFlow, Detection, Alert
from database.connection import get_db
from auth.security import login_required, get_current_user
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    user = get_current_user()
    return render_template('dashboard.html', user=user)

@dashboard_bp.route('/api/dashboard/stats')
@login_required
def get_stats():
    with get_db() as conn:
        cur = conn.cursor()
        
        # Total Flows
        cur.execute('SELECT COUNT(*) FROM network_flows')
        total_flows = cur.fetchone()[0]

        # Total Detections
        cur.execute('SELECT COUNT(*) FROM detections')
        total_detections = cur.fetchone()[0]

        # Active Alerts (NEW or ACKNOWLEDGED)
        cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'ACKNOWLEDGED')")
        active_alerts = cur.fetchone()[0]

        # Critical Alerts
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status IN ('NEW', 'ACKNOWLEDGED')")
        critical_alerts = cur.fetchone()[0]

        # Attack Counts
        cur.execute("SELECT attack_type, COUNT(*) FROM detections GROUP BY attack_type")
        attack_counts = {row[0]: row[1] for row in cur.fetchall()}

        # Severity Counts
        cur.execute("SELECT severity, COUNT(*) FROM detections GROUP BY severity")
        severity_counts = {row[0]: row[1] for row in cur.fetchall()}

    return jsonify({
        'total_flows': total_flows,
        'total_detections': total_detections,
        'active_alerts': active_alerts,
        'critical_alerts': critical_alerts,
        'attacks': {
            'ddos': attack_counts.get('DDOS', 0),
            'port_scan': attack_counts.get('PORT_SCAN', 0),
            'brute_force': attack_counts.get('BRUTE_FORCE', 0),
            'normal': attack_counts.get('NORMAL', 0),
            'unknown': attack_counts.get('UNKNOWN', 0)
        },
        'severity': {
            'low': severity_counts.get('LOW', 0),
            'medium': severity_counts.get('MEDIUM', 0),
            'high': severity_counts.get('HIGH', 0),
            'critical': severity_counts.get('CRITICAL', 0)
        }
    })

@dashboard_bp.route('/api/dashboard/charts')
@login_required
def get_charts():
    with get_db() as conn:
        cur = conn.cursor()
        
        # 1. Attack Types Distribution
        cur.execute("SELECT attack_type, COUNT(*) FROM detections GROUP BY attack_type")
        attack_dist = {r[0]: r[1] for r in cur.fetchall()}

        # 2. Severity Distribution
        cur.execute("SELECT severity, COUNT(*) FROM detections GROUP BY severity")
        severity_dist = {r[0]: r[1] for r in cur.fetchall()}

        # 3. Timeline / Recent Activity (Last 10 intervals)
        cur.execute("""
            SELECT substr(detected_at, 1, 16) as time_slot, attack_type, COUNT(*)
            FROM detections
            GROUP BY time_slot, attack_type
            ORDER BY time_slot DESC
            LIMIT 30
        """)
        timeline_rows = cur.fetchall()

        timeline_data = {}
        for r in timeline_rows:
            slot = r[0]
            if slot not in timeline_data:
                timeline_data[slot] = {'DDOS': 0, 'PORT_SCAN': 0, 'BRUTE_FORCE': 0, 'NORMAL': 0, 'UNKNOWN': 0}
            timeline_data[slot][r[1]] = r[2]

        sorted_slots = sorted(timeline_data.keys())[-12:]
        timeline_chart = {
            'labels': [s.split('T')[-1] if 'T' in s else s for s in sorted_slots],
            'ddos': [timeline_data[s].get('DDOS', 0) for s in sorted_slots],
            'port_scan': [timeline_data[s].get('PORT_SCAN', 0) for s in sorted_slots],
            'brute_force': [timeline_data[s].get('BRUTE_FORCE', 0) for s in sorted_slots],
            'normal': [timeline_data[s].get('NORMAL', 0) for s in sorted_slots],
            'unknown': [timeline_data[s].get('UNKNOWN', 0) for s in sorted_slots]
        }

        # 4. Traffic Flow Statistics (Avg Packet Rate vs Byte Rate)
        cur.execute("""
            SELECT AVG(packets_per_second), AVG(bytes_per_second), MAX(packets_per_second), MAX(bytes_per_second)
            FROM network_flows
        """)
        traffic_stats = cur.fetchone()

    return jsonify({
        'attack_distribution': attack_dist,
        'severity_distribution': severity_dist,
        'timeline': timeline_chart,
        'traffic_averages': {
            'avg_pps': round(traffic_stats[0] or 0, 2),
            'avg_bps': round(traffic_stats[1] or 0, 2),
            'max_pps': round(traffic_stats[2] or 0, 2),
            'max_bps': round(traffic_stats[3] or 0, 2)
        }
    })
