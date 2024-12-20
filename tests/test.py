import json
from core.api.models import User
import requests


def get_user_by_id_admin():
    """Test retrieving a specific user by ID as an admin."""
    requests.post(
        '/login',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }))

    # user = User.query.filter_by(email='testuser@example.com').first()
    users = User.query.all()
    print(users)

    # response = requests.get(f'/users/{user[0].id}')
    assert response.status_code == 200
    # assert json.loads(response.data)['user']['username'] == 'testuser'
    requests.post(
        '/logout',
        data=json.dumps({
            'username': 'adminuser',
            'email': 'adminuser@example.com',
            'password': 'password'
        }))


get_user_by_id_admin()
