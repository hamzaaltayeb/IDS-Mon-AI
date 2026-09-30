from flask import Blueprint, render_template, request, jsonify
from database.models import NetworkFlow, Detection, Alert, SystemLog
from database.connection import get_db
from auth.security import login_required, get_current_user
from engine.pipeline import pipeline
from engine.live_capture import live_capture_manager

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/monitoring')
@login_required
def index():
    user = get_current_user()
    return render_template('monitoring.html', user=user)

@monitoring_bp.route('/api/flows', methods=['GET'])
@login_required
def get_flows():
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    traffic_source = request.args.get('source')
    session_id = request.args.get('session_id')
    
    flows = NetworkFlow.get_all(limit=limit, offset=offset, traffic_source=traffic_source, session_id=session_id)
    total = NetworkFlow.count(traffic_source=traffic_source, session_id=session_id)
    return jsonify({
        'total': total,
        'flows': [f.to_dict() for f in flows]
    })

@monitoring_bp.route('/api/flows/ingest', methods=['POST'])
@login_required
def ingest_flow():
    data = request.get_json() or {}
    result = pipeline.process_flow(data, persist=True)
    return jsonify({
        'success': True,
        'result': result
    })


# --- LIVE NETWORK MONITORING ENDPOINTS ---
@monitoring_bp.route('/api/monitoring/interfaces', methods=['GET'])
@login_required
def get_interfaces():
    """
    Returns the list of available host network interfaces with full metadata.
    """
    interfaces = live_capture_manager.get_available_interfaces()
    default_iface = 'wlp108s0' if any(i['name'] == 'wlp108s0' for i in interfaces) else (interfaces[0]['name'] if interfaces else 'lo')
    return jsonify({
        'interfaces': interfaces,
        'default': default_iface
    })

@monitoring_bp.route('/api/monitoring/live/start', methods=['POST'])
@login_required
def start_live_monitoring():
    """
    LIVE MODE: Starts real-time packet capture on the selected network interface.
    """
    data = request.get_json() or {}
    interface = data.get('interface')
    bpf_filter = data.get('filter', 'ip')
    flow_timeout = float(data.get('flow_timeout', 10.0))
    debug_capture = bool(data.get('debug_capture', False))

    success, message = live_capture_manager.start_capture(
        interface=interface,
        bpf_filter=bpf_filter,
        flow_timeout=flow_timeout,
        debug_capture=debug_capture
    )
    status = live_capture_manager.get_status()

    return jsonify({
        'success': success,
        'message': message,
        'status': status
    }), (200 if success else 400)

@monitoring_bp.route('/api/monitoring/live/stop', methods=['POST'])
@login_required
def stop_live_monitoring():
    """
    LIVE MODE: Stops real-time packet capture and flushes active flows.
    """
    success, message = live_capture_manager.stop_capture()
    status = live_capture_manager.get_status()
    return jsonify({
        'success': success,
        'message': message,
        'status': status
    })

@monitoring_bp.route('/api/monitoring/live/status', methods=['GET'])
@login_required
def get_live_status():
    """
    Returns live packet capture telemetry status.
    """
    status = live_capture_manager.get_status()
    return jsonify(status)

# --- RESET / PURGE ENDPOINT ---
@monitoring_bp.route('/api/monitoring/reset', methods=['POST'])
@login_required
def reset_monitoring_data():
    """
    SOC OPERATIONAL RESET: Purges all telemetry flows, detections, and alerts,
    resets live stream counters, and starts with a pristine clean slate.
    """
    user = get_current_user()
    try:
        # 1. Stop live capture if running
        if live_capture_manager.is_running:
            live_capture_manager.stop_capture()

        # 2. Reset in-memory live capture manager counters
        with live_capture_manager.lock:
            live_capture_manager.packets_captured = 0
            live_capture_manager.packets_parsed = 0
            live_capture_manager.finalized_flows = 0
            live_capture_manager.analyzed_flows = 0
            live_capture_manager.detections_count = 0
            live_capture_manager.alerts_count = 0
            live_capture_manager.flow_table = live_capture_manager.flow_table.__class__(flow_timeout=live_capture_manager.flow_timeout)
            live_capture_manager.start_time = None
            live_capture_manager.stop_time = None

        # 3. Purge tables from database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM alerts')
            cur.execute('DELETE FROM detections')
            cur.execute('DELETE FROM network_flows')
            
            # Reset SQLite auto-increment sequences if sqlite
            try:
                cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'detections', 'network_flows')")
            except Exception:
                pass

        # 4. Record audit log
        SystemLog.create(
            user_id=user.id if user else 1,
            action='TELEMETRY_RESET',
            description='Operator purged all network flows, detections, and alerts to reset telemetry.',
            ip_address=request.remote_addr or '127.0.0.1'
        )

        return jsonify({
            'success': True,
            'message': 'All network flows, detections, and alerts have been purged successfully. Telemetry reset to 0.',
            'status': live_capture_manager.get_status()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
