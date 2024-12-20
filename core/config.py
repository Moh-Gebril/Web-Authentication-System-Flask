"""
Configuration settings for different environments (Development, Testing, Production).
Includes settings for database, session management, and security features.
"""

import os
import redis
from datetime import timedelta


class Config:
    """Base configuration class with common settings."""

    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SECRET_KEY = os.environ.get('SECRET_KEY', 'defaultsecretkey')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DB_URL', 'postgresql://postgres:postgres@localhost:5432/postgres')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"

    # Session configuration
    SESSION_TYPE = "redis"
    SESSION_REDIS = redis.from_url("redis://redis:6379")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=1)
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class DevelopmentConfig(Config):
    """Development environment specific configuration."""

    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    DEBUG_TB_ENABLED = True


class TestingConfig(Config):
    """Testing environment specific configuration."""

    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/test'
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production environment specific configuration."""

    DEBUG = False
    DEBUG_TB_ENABLED = False
