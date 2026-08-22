from flask import Blueprint, render_template, request, jsonify, abort
from database.models import Detection
from auth.security import login_required, get_current_user

detection_bp = Blueprint('detection', __name__)

@detection_bp.route('/detections')
@login_required
def index():
    user = get_current_user()
    return render_template('detections.html', user=user)

@detection_bp.route('/detections/<int:detection_id>')
@login_required
def detail(detection_id):
    user = get_current_user()
    det = Detection.find_by_id_with_flow(detection_id)
    if not det:
        abort(404)
    return render_template('detection_detail.html', user=user, detection=det)

@detection_bp.route('/api/detections', methods=['GET'])
@login_required
def get_detections():
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    attack_type = request.args.get('attack_type', 'ALL')
    severity = request.args.get('severity', 'ALL')

    detections = Detection.get_all(limit=limit, offset=offset, attack_type=attack_type, severity=severity)
    total = Detection.count()
    return jsonify({
        'total': total,
        'detections': detections
    })

@detection_bp.route('/api/detections/<int:detection_id>', methods=['GET'])
@login_required
def get_detection(detection_id):
    det = Detection.find_by_id_with_flow(detection_id)
    if not det:
        return jsonify({'error': 'Detection not found'}), 404
    return jsonify(det)
