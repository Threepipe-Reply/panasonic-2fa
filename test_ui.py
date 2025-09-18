import pytest
from app import app, db, User
from flask_bcrypt import Bcrypt

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client

def test_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Panasonic 2FA' in response.data

def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

def test_login_redirect(client):
    response = client.get('/tokens')
    assert response.status_code == 302  # Redirect to login

def test_login_form(client):
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    assert response.status_code == 200  # Invalid login stays on page