import pytest
from core.api.models import db
from core.api.routes import routes as api_routes
from flask import Flask
import core.config as config


@pytest.fixture(scope='module')
def test_client():
    # Create a Flask application instance for testing
    app = Flask(__name__)
    app.config.from_object(config.DevelopmentConfig)

    # Initialize the database with the app context
    db.init_app(app)

    # Register routes with the application
    app.register_blueprint(api_routes)

    # Create a test client using the Flask application configured for testing
    client = app.test_client()

    with app.app_context():
        db.session.remove()
        db.drop_all()

    with app.app_context():
        db.create_all()

    yield client

    # Clear the database before each test
    with app.app_context():
        db.session.remove()
        db.drop_all()
