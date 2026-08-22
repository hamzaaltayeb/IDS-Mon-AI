from flask import request, session
from database.models import SystemLog

def log_action(action, description='', user_id=None):
    uid = user_id or session.get('user_id')
    ip = request.remote_addr if request else '127.0.0.1'
    SystemLog.create(user_id=uid, action=action, description=description, ip_address=ip)
