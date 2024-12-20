"""
Main application entry point for the Flask Authentication System.
This module initializes the Flask application, configures it, and sets up all required extensions.
"""

from flask import Flask
from core.api.routes import routes as api_routes
from core.extensions import server_session
from core.api.models import db
import core.config as config


def create_app(config_class=config.DevelopmentConfig):
    """
    Create and configure the Flask application.
    
    Args:
        config_class: Configuration class to use (default: DevelopmentConfig)
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register blueprints and initialize extensions
    app.register_blueprint(api_routes)
    server_session.init_app(app)
    db.init_app(app)

    # Initialize database tables
    with app.app_context():
        db.session.remove()
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=4000)
