"""
Database models for the authentication system.
Defines the User model with role-based authentication support.
"""

import uuid
from sqlalchemy.dialects.postgresql import UUID
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    """
    User model representing application users with role-based authentication.

    Attributes:
        id (UUID): Unique identifier for the user
        username (str): Unique username
        email (str): Unique email address
        password_hash (str): Hashed password using PBKDF2-SHA256
        role (str): User role ('admin' or 'user')
    """

    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True,
                   default=uuid.uuid4, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')

    def json(self):
        """
        Convert user object to JSON representation.

        Returns:
            dict: JSON representation of user
        """
        return {'id': self.id, 'username': self.username, 'email': self.email}

    def set_password(self, password):
        """
        Hash and set the user's password.

        Args:
            password (str): Plain text password to hash
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, entered_password):
        """
        Verify if entered password matches stored hash.

        Args:
            entered_password (str): Password to verify

        Returns:
            bool: True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, entered_password)
