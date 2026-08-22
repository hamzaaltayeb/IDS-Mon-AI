from flask import Blueprint, render_template, request, jsonify
from database.models import SystemLog
from auth.security import admin_required, get_current_user

log_bp = Blueprint('log', __name__)

@log_bp.route('/logs')
@admin_required
def index():
    user = get_current_user()
    return render_template('system_logs.html', user=user)

@log_bp.route('/api/logs', methods=['GET'])
@admin_required
def get_logs():
    limit = min(int(request.args.get('limit', 100)), 300)
    offset = int(request.args.get('offset', 0))
    search = request.args.get('search', '').strip() or None

    logs = SystemLog.get_all(limit=limit, offset=offset, action_search=search)
    return jsonify(logs)
