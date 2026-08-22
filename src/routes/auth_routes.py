from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from database.models import User, SystemLog
from auth.security import login_user, logout_user, get_current_user, login_required
from auth.audit import log_action

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('dashboard.index'))

    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        user = User.find_by_username_or_email(identifier)
        if user and user.verify_password(password):
            if not user.is_active:
                error = "Account is disabled. Please contact the system administrator."
                log_action('LOGIN_DISABLED', f"Failed login attempt for deactivated user: {identifier}")
            else:
                login_user(user)
                if user.must_change_password:
                    flash('You are using a default password. Please update your password.', 'warning')
                    return redirect(url_for('auth.profile'))
                next_url = request.args.get('next') or url_for('dashboard.index')
                return redirect(next_url)
        else:
            error = "Invalid username/email or password."
            log_action('LOGIN_FAILED', f"Failed login attempt for: {identifier}")

    return render_template('login.html', error=error)

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    message = None
    error = None

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not user.verify_password(current_password):
            error = "Current password is incorrect."
        elif len(new_password) < 8:
            error = "New password must be at least 8 characters long."
        elif new_password != confirm_password:
            error = "New passwords do not match."
        else:
            User.update_password(user.id, new_password)
            log_action('PASSWORD_CHANGE', f"User {user.username} changed their password")
            message = "Password updated successfully."
            session['must_change_password'] = False

    return render_template('profile.html', user=user, message=message, error=error)

# API Endpoints
@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')

    user = User.find_by_username_or_email(identifier)
    if user and user.verify_password(password):
        if not user.is_active:
            return jsonify({'error': 'Account is disabled', 'code': 403}), 403
        login_user(user)
        return jsonify({'success': True, 'user': user.to_dict()})
    return jsonify({'error': 'Invalid credentials', 'code': 401}), 401

@auth_bp.route('/api/auth/logout', methods=['POST'])
def api_logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out'})

@auth_bp.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
    user = get_current_user()
    return jsonify(user.to_dict())

@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    user = get_current_user()
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not user.verify_password(current_password):
        return jsonify({'error': 'Current password incorrect'}), 400
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    User.update_password(user.id, new_password)
    log_action('PASSWORD_CHANGE', f"User {user.username} updated password via API")
    session['must_change_password'] = False
    return jsonify({'success': True, 'message': 'Password updated successfully'})
