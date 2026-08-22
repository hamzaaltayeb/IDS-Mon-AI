import os
import sys
from flask import Flask, render_template, jsonify

# Add src to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.connection import init_db
from database.models import Alert
from auth.security import get_current_user, is_admin

# Import all Route Blueprints
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.monitoring_routes import monitoring_bp
from routes.detection_routes import detection_bp
from routes.alert_routes import alert_bp
from routes.report_routes import report_bp
from routes.user_routes import user_bp
from routes.log_routes import log_bp

def create_app():
    templates_path = os.path.join(os.path.dirname(BASE_DIR), 'templates')
    static_path = os.path.join(os.path.dirname(BASE_DIR), 'static')

    app = Flask(__name__, template_folder=templates_path, static_folder=static_path)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ai-nsms-soc-secret-production-key-2026')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Initialize Database
    with app.app_context():
        init_db()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(detection_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(log_bp)

    # Context Processors for Templates
    @app.context_processor
    def inject_global_context():
        current_user = get_current_user()
        active_alerts_count = Alert.count(status='NEW') if current_user else 0
        return {
            'current_user': current_user,
            'is_admin': is_admin(),
            'active_alerts_count': active_alerts_count
        }

    # Error Handlers
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html', message='Access Forbidden: Insufficient role permissions.'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('errors/500.html'), 500

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    print("==================================================================")
    print("🛡️  Intelligent Network Security Monitoring System (AI-NSMS) 🛡️")
    print(f"🚀 SOC Operations Center running at: http://localhost:{port}")
    print("👤 Admin Account:    admin   / Admin@12345")
    print("👤 Analyst Account:  analyst / Analyst@12345")
    print("==================================================================")
    app.run(debug=True, host=host, port=port)
