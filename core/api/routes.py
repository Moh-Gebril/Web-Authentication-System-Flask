"""
Flask Blueprint for user authentication and management routes.

This module provides a complete REST API for user authentication and management, including:
- User registration and login
- Session management
- User profile management
- Role-based access control
- Rate limiting on sensitive endpoints

All routes implement proper error handling and logging.
"""

from flask import Blueprint, request, jsonify, make_response, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError
import logging

from core.api.models import db, User
from core.utils import login_required, admin_role_required

routes = Blueprint('routes', __name__)

limiter = Limiter(
    get_remote_address,
    app=None,
    default_limits=["200 per day", "50 per hour"]
)


@routes.route('/test', methods=['GET'])
@limiter.limit("5 per minute")
@login_required
def test():
    """
    Test endpoint to verify authentication and rate limiting.

    Rate limit: 5 requests per minute
    Authentication: Required

    Returns:
        JSON response with status code:
        - 200: Success
        - 401: Unauthorized
        - 429: Too Many Requests
    """
    return make_response(jsonify({'message': 'test route'}), 200)


@routes.route('/@me')
def get_current_user():
    """
    Get the currently authenticated user's profile.

    Uses session-based authentication to identify the current user.

    Returns:
        JSON response with status code:
        - 200: Success with user data
        - 401: Unauthorized
        - 500: Server error
    """
    user_id = session.get("user_id")

    if not user_id:
        return make_response(
            jsonify({'message': 'Unauthorized user', 'user_id': user_id}),
            401
        )

    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return make_response(
                jsonify({'message': 'Unauthorized user', 'user_id': user_id}),
                401
            )
        return make_response(
            jsonify({'Username': user.username, 'Email': user.email}),
            200
        )

    except SQLAlchemyError as e:
        return make_response(
            jsonify({'message': 'Database error occurred', 'error': str(e)}),
            500
        )
    except Exception as e:
        return make_response(
            jsonify({'message': 'Error getting current user', 'error': str(e)}),
            500
        )


@routes.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    """
    Register a new user in the system.

    Rate limit: 10 requests per minute

    Expected JSON payload:
    {
        "username": "string",
        "email": "string",
        "password": "string",
        "role": "string"  // "admin" or "user"
    }

    Returns:
        JSON response with status code:
        - 201: User created successfully
        - 400: Invalid input data
        - 409: User already exists
        - 429: Too many requests
        - 500: Server error
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'email' not in data:
            return make_response(jsonify({'message': 'Invalid input data'}), 400)

        if is_user_exists(data['email']):
            return make_response(jsonify({'message': 'User already exists'}), 409)

        password_hash = generate_password_hash(
            data.get('password'),
            method='pbkdf2:sha256'
        )

        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=password_hash,
            role=data['role']
        )

        db.session.add(new_user)
        db.session.commit()

        logging.info(f"User {data['username']} created successfully.")
        return make_response(jsonify({'message': 'User created'}), 201)

    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        return make_response(
            jsonify({'message': 'Error creating user', 'error': str(e)}),
            500
        )


@routes.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and create a new session.

    Expected JSON payload:
    {
        "username": "string",
        "email": "string",
        "password": "string"
    }

    Session handling:
    - Clears any existing session
    - Creates new session with user ID
    - Sets session to permanent (expires based on PERMANENT_SESSION_LIFETIME)
    - Forces session ID regeneration

    Returns:
        JSON response with status code:
        - 200: Login successful
        - 400: Invalid input data
        - 401: Invalid credentials
        - 500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No input data provided")

        if not all(k in data for k in ('username', 'email', 'password')):
            return make_response(
                jsonify(
                    {'message': 'Invalid input data: username, email, and password are required'}),
                400
            )

        user = User.query.filter_by(username=data['username']).first()
        if user is None or not user.check_password(data['password']):
            return make_response(
                jsonify({'message': 'Unauthorized user or incorrect credentials'}),
                401
            )

        session.clear()
        session["user_id"] = user.id
        session.permanent = True
        session.modified = True

        return jsonify({'message': 'Login successful', 'user id': user.id}), 200

    except ValueError as e:
        return make_response(
            jsonify({'message': 'Invalid password format', 'error': str(e)}),
            400
        )
    except SQLAlchemyError as e:
        return make_response(
            jsonify({'message': 'Database error occurred', 'error': str(e)}),
            500
        )
    except Exception as e:
        return make_response(
            jsonify({'message': 'An unexpected error occurred', 'error': str(e)}),
            500
        )


@routes.route('/logout', methods=['POST'])
def logout():
    """
    Log out the current user by clearing the session.

    Session handling:
    - Clears the current session data, effectively logging the user out
    - Session is fully terminated to ensure security

    Returns:
        JSON response with status code:
        - 200: Logout successful
        - 401: User not logged in
        - 500: Server error
    """
    try:
        # Check if user is logged in by checking if the session contains 'user_id'
        if "user_id" not in session:
            return make_response(
                jsonify(
                    {'message': 'No active session found. User is not logged in.'}),
                401
            )

        # Clear the session to log out the user
        session.clear()
        session.modified = True  # Mark session as modified to ensure it clears

        return jsonify({'message': 'Logout successful'}), 200

    except Exception as e:
        # Handle any unexpected server errors
        return make_response(
            jsonify(
                {'message': 'An unexpected error occurred during logout', 'error': str(e)}),
            500
        )


@routes.route('/users', methods=['GET'])
@admin_role_required
def get_users():
    """
    Get all users in the system.

    Authentication: Admin role required

    Returns:
        JSON response with status code:
        - 200: List of users
        - 401: Unauthorized
        - 403: Forbidden (not admin)
        - 500: Server error
    """
    try:
        users = User.query.all()
        return make_response(jsonify([user.json() for user in users]), 200)
    except Exception as e:
        logging.error(f"Error getting users: {str(e)}")
        return make_response(
            jsonify({'message': 'Error getting users', 'error': str(e)}),
            500
        )


@routes.route('/users/<string:username>', methods=['GET'])
@admin_role_required
def get_user(username):
    """
    Get a specific user by ID.

    Authentication: Admin role required

    Args:
        username (str): User name to retrieve

    Returns:
        JSON response with status code:
        - 200: User data
        - 401: Unauthorized
        - 403: Forbidden (not admin)
        - 404: User not found
        - 500: Server error
    """
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            return make_response(jsonify({'user': user.json()}), 200)
        return make_response(jsonify({'message': 'User not found'}), 404)
    except Exception as e:
        logging.error(f"Error getting user by name: {str(e)}")
        return make_response(
            jsonify({'message': 'Error getting user', 'error': str(e)}),
            500
        )


@routes.route('/users/<string:username>', methods=['PUT'])
@login_required
def update_user(username):
    """
    Update a user's profile.

    Authentication: Login required
    Authorization: Users can update their own profile, or admins can update any user's profile.

    Expected JSON payload (all fields optional):
    {
        "username": "string",
        "email": "string",
        "password": "string"
    }

    Returns:
        JSON response with status code:
        - 200: User updated
        - 401: Unauthorized (login required)
        - 403: Forbidden (not authorized to update)
        - 404: User not found
        - 500: Server error
    """
    try:
        # Get the logged-in user's ID from the session
        logged_in_user = User.query.filter_by(
            id=session.get('user_id')).first()

        # Fetch the logged-in user from the database
        user = User.query.filter_by(username=username).first()

        if not logged_in_user:
            return make_response(jsonify({'message': 'Unauthorized'}), 401)

        if not user:
            return make_response(jsonify({'message': 'User not found'}), 404)

        # Get the target email from the request payload (optional)
        data = request.get_json()

        if logged_in_user.id != user.id and logged_in_user.role != 'admin':
            return make_response(
                jsonify(
                    {'message': 'Forbidden: You can only update your own profile.'}),
                403
            )

        data = request.get_json()

        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user.password_hash = generate_password_hash(
                data['password'], method='pbkdf2:sha256')

        # Commit the changes to the database
        db.session.commit()

        logging.info(f"User {user.username} updated successfully.")
        return make_response(jsonify({'message': 'User updated successfully'}), 200)

    except Exception as e:
        logging.error(f"Error updating user: {str(e)}")
        return make_response(
            jsonify({'message': 'Error updating user', 'error': str(e)}),
            500
        )


@routes.route('/users/<string:username>', methods=['DELETE'])
@login_required
def delete_user(username):
    """
    Delete a user's account.

    Authentication: Login required
    Authorization: Users can delete their own account, or admins can delete any user's account.

    Args:
        username (str): Username of the user to delete

    Returns:
        JSON response with status code:
        - 200: User deleted
        - 401: Unauthorized (login required)
        - 403: Forbidden (not authorized to delete)
        - 404: User not found
        - 500: Server error
    """
    try:
        # Get the logged-in user's ID from the session
        logged_in_user = User.query.filter_by(
            id=session.get('user_id')).first()

        if not logged_in_user:
            return make_response(jsonify({'message': 'Unauthorized'}), 401)

        # Fetch the user to be deleted by username
        user_to_delete = User.query.filter_by(username=username).first()

        if not user_to_delete:
            return make_response(jsonify({'message': 'User not found'}), 404)

        # Check if the logged-in user is trying to delete their own account or is an admin
        if logged_in_user.id != user_to_delete.id and logged_in_user.role != 'admin':
            return make_response(
                jsonify(
                    {'message': 'Forbidden: You can only delete your own account.'}),
                403
            )

        # Remove the user from the database
        db.session.delete(user_to_delete)
        db.session.commit()

        logging.info(f"User {user_to_delete.username} deleted successfully.")
        return make_response(jsonify({'message': 'User deleted successfully'}), 200)

    except Exception as e:
        logging.error(f"Error deleting user: {str(e)}")
        return make_response(
            jsonify({'message': 'Error deleting user', 'error': str(e)}),
            500
        )


def is_user_exists(email: str) -> bool:
    """
    Check if a user with the given email already exists.

    Args:
        email (str): Email address to check

    Returns:
        bool: True if user exists, False otherwise

    Raises:
        SQLAlchemyError: If database query fails
    """
    try:
        user_exists = User.query.filter_by(email=email).first()
        return user_exists is not None
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise e
