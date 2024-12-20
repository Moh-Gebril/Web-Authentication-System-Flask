import json
from core.api.models import User


def test_register_user(test_client):
    """Test user registration."""
    response = test_client.post(
        '/register',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password',
            'role': 'user'
        }),
        content_type='application/json'
    )
    assert response.status_code == 201
    assert b'User created' in response.data


def test_register_existing_user(test_client):
    # Attempt to register the same email
    response = test_client.post(
        '/register',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password',
            'role': 'user'
        }),
        content_type='application/json'
    )
    assert response.status_code == 409
    assert b'User already exists' in response.data


def test_login_success(test_client):
    """Test successful login."""

    response = test_client.post(
        '/login',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )
    assert response.status_code == 200
    assert b'Login successful' in response.data
    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_login_failure(test_client):
    """Test failed login due to invalid credentials."""
    response = test_client.post(
        '/login',
        data=json.dumps({
            'username': 'wronguser',
            'email': 'wronguser@example.com',
            'password': 'wrongpassword'
        }),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert b'Unauthorized user or incorrect credentials' in response.data


def test_get_current_user_authenticated(test_client):
    """Test getting the currently authenticated user."""
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )
    response = test_client.get('/@me')
    assert response.status_code == 200
    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_get_current_user_unauthenticated(test_client):
    """Test getting the current user without authentication."""
    response = test_client.get('/@me')
    assert response.status_code == 401
    assert b'Unauthorized user' in response.data


def test_get_users_admin(test_client):
    """Test retrieving all users as an admin."""
    test_client.post(
        '/register',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password',
            'role': 'admin'
        }),
        content_type='application/json'
    )
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )
    response = test_client.get('/users')
    assert response.status_code == 200
    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_get_user_by_id_admin(test_client):
    """Test retrieving a specific user by username as an admin."""
    # Log in as admin
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )

    # Use app context to query the user
    with test_client.application.app_context():
        user = User.query.filter_by(username='testuser').first()

    # Make a request to the user retrieval endpoint
    response = test_client.get(f'/users/{user.username}')

    # Assert the response is successful and contains the correct data
    assert response.status_code == 200
    assert json.loads(response.data)['user']['username'] == 'testuser'

    # Log out the admin user
    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_update_user_unauthorized(test_client):
    """Test updating user without authentication."""
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )

    response = test_client.put(
        '/users/adminuser',
        data=json.dumps({
            'username': 'updateduser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert b'Forbidden' in response.data

    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_update_user(test_client):
    """Test updating the user's own profile."""
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )

    response = test_client.put(
        '/users/testuser',
        data=json.dumps({
            'username': 'updateduser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )
    assert response.status_code == 200
    assert b'User updated' in response.data

    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'updateduser',
            'email': 'testuser@example.com',
            'password': 'password'
        }),
        content_type='application/json'
    )


def test_delete_user_admin(test_client):
    """Test deleting a user as an admin."""
    test_client.post(
        '/register',
        data=json.dumps({
            'username': 'deleteduser',
            'email': 'deleteduser@example.com',
            'password': 'password',
            'role': 'user'
        }),
        content_type='application/json'
    )
    test_client.post(
        '/login',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password',
            'role': 'admin'
        }),
        content_type='application/json'
    )

    response = test_client.delete(f'/users/deleteduser')
    assert response.status_code == 200
    assert b'User deleted' in response.data

    test_client.post(
        '/logout',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password',
            'role': 'admin'
        }),
        content_type='application/json'
    )
