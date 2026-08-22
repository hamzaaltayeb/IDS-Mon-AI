from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from database.models import User
from auth.security import admin_required, get_current_user
from auth.audit import log_action

user_bp = Blueprint('user', __name__)

@user_bp.route('/users')
@admin_required
def index():
    user = get_current_user()
    users = User.get_all()
    return render_template('users.html', user=user, users=users)

@user_bp.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.get_all()
    return jsonify([u.to_dict() for u in users])

@user_bp.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'SECURITY_ANALYST').upper()
    must_change = bool(data.get('must_change_password', True))

    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400
    if role not in ['ADMIN', 'SECURITY_ANALYST']:
        return jsonify({'error': 'Invalid role'}), 400
    if User.find_by_username_or_email(username) or User.find_by_username_or_email(email):
        return jsonify({'error': 'Username or email already exists'}), 409

    user_id = User.create(username, email, password, role, must_change)
    log_action('USER_CREATE', f"Created new user: {username} ({role})")

    return jsonify({
        'success': True,
        'user_id': user_id,
        'message': f"User {username} created successfully."
    })

@user_bp.route('/api/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    current = get_current_user()
    if current.id == user_id:
        return jsonify({'error': 'Cannot deactivate your own account'}), 400

    target = User.find_by_id(user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    new_status = not target.is_active
    User.toggle_active(user_id, new_status)
    action_name = 'Activated' if new_status else 'Deactivated'
    log_action('USER_STATUS_CHANGE', f"{action_name} user: {target.username}")

    return jsonify({
        'success': True,
        'is_active': new_status,
        'message': f"User {target.username} has been {action_name}."
    })

@user_bp.route('/api/users/<int:user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    current = get_current_user()
    if current.id == user_id:
        return jsonify({'error': 'Cannot change your own role'}), 400

    data = request.get_json() or {}
    new_role = data.get('role', '').upper()
    if new_role not in ['ADMIN', 'SECURITY_ANALYST']:
        return jsonify({'error': 'Invalid role'}), 400

    target = User.find_by_id(user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    User.update_role(user_id, new_role)
    log_action('USER_ROLE_CHANGE', f"Changed role for {target.username} to {new_role}")

    return jsonify({
        'success': True,
        'role': new_role,
        'message': f"Role for {target.username} updated to {new_role}."
    })

@user_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    current = get_current_user()
    if current.id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    target = User.find_by_id(user_id)
    if not target:
        return jsonify({'error': 'User not found'}), 404

    User.delete(user_id)
    log_action('USER_DELETE', f"Deleted user: {target.username}")

    return jsonify({
        'success': True,
        'message': f"User {target.username} deleted."
    })
