from flask import Blueprint, render_template, request, jsonify
from database.models import Alert
from auth.security import login_required, get_current_user
from auth.audit import log_action

alert_bp = Blueprint('alert', __name__)

@alert_bp.route('/alerts')
@login_required
def index():
    user = get_current_user()
    return render_template('alerts.html', user=user)

@alert_bp.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    status = request.args.get('status', 'ALL')
    severity = request.args.get('severity', 'ALL')

    alerts = Alert.get_all(limit=limit, offset=offset, status=status, severity=severity)
    total_active = Alert.count(status='NEW')
    return jsonify({
        'active_count': total_active,
        'alerts': alerts
    })

@alert_bp.route('/api/alerts/<int:alert_id>', methods=['PATCH'])
@login_required
def update_alert(alert_id):
    data = request.get_json() or {}
    new_status = data.get('status', '').upper()

    if new_status not in ['NEW', 'ACKNOWLEDGED', 'RESOLVED']:
        return jsonify({'error': 'Invalid status'}), 400

    alert = Alert.find_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    Alert.update_status(alert_id, new_status)
    log_action('ALERT_STATUS_UPDATE', f"Alert #{alert_id} ({alert.title}) status changed to {new_status}")

    return jsonify({
        'success': True,
        'alert_id': alert_id,
        'status': new_status
    })
