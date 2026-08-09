"""
Authentication Blueprint for Cloud Network Anomaly Detection.
Provides user registration, login, logout, and current user retrieval APIs.
"""

import re
import logging
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from backend.db import db, User

# Define Blueprint
auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Regular expression for email validation
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


def validate_registration_input(data):
    """Validate username, email, and password format."""
    if not data or not isinstance(data, dict):
        return False, "Request body must be a valid JSON object."

    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long."

    if not email or not re.match(EMAIL_REGEX, email):
        return False, "Invalid email address format."

    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long."

    return True, None


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    POST /api/auth/register
    Register a new user account.
    Payload: { "name": "", "username": "", "email": "", "password": "" }
    """
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Request body must be a valid JSON object.'}), 400

        name = data.get('name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long.'}), 400

        if not email or not re.match(EMAIL_REGEX, email):
            return jsonify({'error': 'Invalid email address format.'}), 400

        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long.'}), 400

        # Ensure database tables exist before querying
        try:
            db.create_all()
        except Exception as table_err:
            logger.warning(f"Table verification in register: {table_err}")

        # Check for duplicate username / email
        try:
            existing_username = User.query.filter_by(username=username).first()
            if existing_username:
                logger.warning(f"Registration conflict: Username '{username}' already exists.")
                return jsonify({'error': 'Username already registered. Please login or choose a different username.'}), 409

            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                logger.warning(f"Registration conflict: Email '{email}' already exists.")
                return jsonify({'error': 'Email address already registered. Please login or use a different email.'}), 409
        except Exception as query_err:
            logger.error(f"Database query error during registration check: {query_err}")
            return jsonify({
                'error': f'Database Connection Error: Unable to query MySQL ({str(query_err)}). Please verify Render Environment Variables (DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME).'
            }), 500

        # Hash password securely using werkzeug.security
        hashed_pw = generate_password_hash(password)

        # Create new user in database
        new_user = User(
            name=name if name else username,
            username=username,
            email=email,
            password_hash=hashed_pw,
            role='user'
        )

        db.session.add(new_user)
        db.session.commit()

        logger.info(f"User registered successfully: ID={new_user.id}, Username={username}")

        return jsonify({
            'message': 'Account created successfully',
            'user': new_user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Internal error during registration: {e}", exc_info=True)
        return jsonify({'error': f'Registration Error: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    POST /api/auth/login
    Authenticate user and initiate session.
    """
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Request body must be a valid JSON object.'}), 400

        login_identifier = data.get('username') or data.get('email')
        password = data.get('password')

        if not login_identifier or not password:
            return jsonify({'error': 'Username/Email and Password are required fields.'}), 400

        login_identifier = login_identifier.strip()

        # Ensure database tables exist before querying
        try:
            db.create_all()
        except Exception as table_err:
            logger.warning(f"Table verification in login: {table_err}")

        # Find user by username or email
        try:
            user = User.query.filter(
                (User.username == login_identifier) | (User.email == login_identifier.lower())
            ).first()
        except Exception as query_err:
            logger.error(f"Database query error during login check: {query_err}")
            return jsonify({
                'error': f'Database Connection Error: Unable to query MySQL ({str(query_err)}). Please verify Render Environment Variables (DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME).'
            }), 500

        if not user or not check_password_hash(user.password_hash, password):
            logger.warning(f"Failed login attempt for identifier: '{login_identifier}' from IP: {request.remote_addr}")
            return jsonify({'error': 'Invalid username/email or password.'}), 401

        # Successful login -> Set session data
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role

        logger.info(f"Successful login: User ID={user.id}, Username='{user.username}' from IP={request.remote_addr}")

        return jsonify({
            'message': 'Login successful.',
            'user': user.to_dict(),
            'session_id': session.sid if hasattr(session, 'sid') else 'active_session'
        }), 200

    except Exception as e:
        logger.error(f"Internal error during login: {e}", exc_info=True)
        return jsonify({'error': f'Login Error: {str(e)}'}), 500


@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """
    GET /api/auth/me
    Retrieve current authenticated user details.
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized. Please log in first.'}), 401

    try:
        user = User.query.get(user_id)
        if not user:
            session.clear()
            return jsonify({'error': 'Authenticated user not found.'}), 404

        return jsonify({
            'user': user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({'error': f'Database Error: {str(e)}'}), 500


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    POST /api/auth/logout
    Invalidate current session.
    """
    user_id = session.get('user_id')
    username = session.get('username')

    session.clear()
    if user_id:
        logger.info(f"User logged out: ID={user_id}, Username='{username}'")

    return jsonify({'message': 'Logged out successfully.'}), 200
