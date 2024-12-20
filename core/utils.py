from functools import wraps
from flask import session, jsonify, make_response
from core.api.models import User
from sqlalchemy.exc import SQLAlchemyError


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user_id is in the session
        user_id = session.get("user_id")

        if not user_id:
            # If no session ID is found, return unauthorized
            return make_response(jsonify({'message': 'Unauthorized user. Please log in.'}), 401)

        try:
            # Attempt to retrieve the user from the database
            user = User.query.filter_by(id=user_id).first()

            # If no user is found, return unauthorized
            if not user:
                return make_response(jsonify({'message': 'Unauthorized user. Please log in.'}), 401)
        except SQLAlchemyError as e:
            # Handle database errors gracefully
            return make_response(jsonify({'message': 'Database error occurred', 'error': str(e)}), 500)

        # Call the actual route function if the user is authenticated
        return f(*args, **kwargs)

    return decorated_function


def admin_role_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return make_response(jsonify({'message': 'Unauthorized user. Please log in.'}), 401)

        try:
            user = User.query.filter_by(id=user_id).first()
            if not user or user.role != 'admin':
                return make_response(jsonify({'message': 'Unauthorized access. Insufficient permissions.'}), 403)
        except SQLAlchemyError as e:
            return make_response(jsonify({'message': 'Database error occurred', 'error': str(e)}), 500)

        return f(*args, **kwargs)
    return decorated_function
