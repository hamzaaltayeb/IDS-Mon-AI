import functools
from flask import session, redirect, url_for, request, jsonify, abort, render_template
from database.models import User, SystemLog

def login_user(user):
    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    session['email'] = user.email
    session['role'] = user.role
    session['must_change_password'] = user.must_change_password
    User.update_last_login(user.id)
    SystemLog.create(user.id, 'AUTH_LOGIN', f"User {user.username} ({user.role}) logged in successfully", request.remote_addr or '127.0.0.1')

def logout_user():
    user_id = session.get('user_id')
    username = session.get('username', 'Unknown')
    if user_id:
        SystemLog.create(user_id, 'AUTH_LOGOUT', f"User {username} logged out", request.remote_addr or '127.0.0.1')
    session.clear()

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = User.find_by_id(user_id)
    if not user or not user.is_active:
        session.clear()
        return None
    return user

def is_authenticated():
    return 'user_id' in session and get_current_user() is not None

def is_admin():
    return session.get('role') == 'ADMIN'

def login_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            return redirect(url_for('auth.login', next=request.url))
        return view_func(*args, **kwargs)
    return wrapper

def admin_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            return redirect(url_for('auth.login', next=request.url))
        if not is_admin():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Forbidden: Administrator privileges required', 'code': 403}), 403
            return render_template('errors/403.html', message='Access Forbidden: This section requires Administrator privileges.'), 403
        return view_func(*args, **kwargs)
    return wrapper

def analyst_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            return redirect(url_for('auth.login', next=request.url))
        return view_func(*args, **kwargs)
    return wrapper
