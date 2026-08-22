import io
import csv
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, Response
from database.connection import get_db
from auth.security import login_required, get_current_user
from auth.audit import log_action

report_bp = Blueprint('report', __name__)

@report_bp.route('/reports')
@login_required
def index():
    user = get_current_user()
    return render_template('reports.html', user=user)

@report_bp.route('/api/reports/summary', methods=['GET'])
@login_required
def get_summary():
    timeframe = request.args.get('timeframe', '7d')
    
    # Calculate date filter
    now = datetime.now()
    if timeframe == 'today':
        start_date = now.strftime('%Y-%m-%d 00:00:00')
    elif timeframe == '30d':
        start_date = (now - timedelta(days=30)).isoformat()
    elif timeframe == 'custom':
        start_date = request.args.get('start_date', (now - timedelta(days=7)).isoformat())
    else: # default 7d
        start_date = (now - timedelta(days=7)).isoformat()

    with get_db() as conn:
        cur = conn.cursor()

        # Total Detections in range
        cur.execute("SELECT COUNT(*) FROM detections WHERE detected_at >= ?", (start_date,))
        total_detections = cur.fetchone()[0]

        # Attacks in range
        cur.execute("SELECT COUNT(*) FROM detections WHERE detected_at >= ? AND prediction = 'ATTACK'", (start_date,))
        total_attacks = cur.fetchone()[0]

        # Critical Attacks
        cur.execute("SELECT COUNT(*) FROM detections WHERE detected_at >= ? AND severity = 'CRITICAL'", (start_date,))
        critical_count = cur.fetchone()[0]

        # Breakdown by attack type
        cur.execute("""
            SELECT attack_type, COUNT(*) as cnt
            FROM detections
            WHERE detected_at >= ?
            GROUP BY attack_type
            ORDER BY cnt DESC
        """, (start_date,))
        attacks_by_type = {r[0]: r[1] for r in cur.fetchall()}

        # Breakdown by severity
        cur.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM detections
            WHERE detected_at >= ?
            GROUP BY severity
        """, (start_date,))
        severity_dist = {r[0]: r[1] for r in cur.fetchall()}

        # Top 5 Source IPs Flagged
        cur.execute("""
            SELECT f.source_ip, COUNT(*) as cnt, MAX(d.severity) as max_sev, MAX(d.attack_type) as top_attack
            FROM detections d
            JOIN network_flows f ON d.flow_id = f.id
            WHERE d.detected_at >= ? AND d.prediction = 'ATTACK'
            GROUP BY f.source_ip
            ORDER BY cnt DESC
            LIMIT 5
        """, (start_date,))
        top_ips = [{'ip': r[0], 'count': r[1], 'severity': r[2], 'attack': r[3]} for r in cur.fetchall()]

    log_action('REPORT_VIEW', f"Viewed security report summary ({timeframe})")

    return jsonify({
        'timeframe': timeframe,
        'start_date': start_date,
        'total_detections': total_detections,
        'total_attacks': total_attacks,
        'critical_attacks': critical_count,
        'attacks_by_type': attacks_by_type,
        'severity_distribution': severity_dist,
        'top_source_ips': top_ips
    })

@report_bp.route('/api/reports/export', methods=['GET'])
@login_required
def export_report():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT d.detected_at, f.source_ip, f.destination_ip, f.protocol, f.destination_port,
                   d.attack_type, d.threat_score, d.severity, d.confidence, d.indicators
            FROM detections d
            JOIN network_flows f ON d.flow_id = f.id
            ORDER BY d.id DESC
            LIMIT 500
        """)
        rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Detection Time', 'Source IP', 'Destination IP', 'Protocol', 'Port', 'Attack Type', 'Threat Score', 'Severity', 'Confidence', 'Indicators'])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]])

    log_action('REPORT_EXPORT', 'Exported detection logs to CSV')

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=ids_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )
