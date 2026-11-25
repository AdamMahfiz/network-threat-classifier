from src.threat_classifier.auth.auth_manager import AuthManager
from tests.conftest import login


def test_login_success_grants_access(client, make_user):
    user, pw = make_user('analyst1')
    resp = login(client, user, pw)
    assert resp.status_code == 302
    assert client.get('/api/pie').status_code == 200


def test_wrong_password_shows_error(client, make_user):
    user, _ = make_user('analyst2')
    resp = login(client, user, 'wrong-password')
    assert resp.status_code == 200
    assert b'Invalid username or password' in resp.data


def test_lockout_after_repeated_failures(client, make_user):
    user, pw = make_user('analyst3')
    for _ in range(3):  # LOGIN_MAX_FAILURES=3 in conftest
        login(client, user, 'bad')
    resp = login(client, user, pw)  # correct password is refused while locked
    assert resp.status_code == 429
    assert b'Too many failed attempts' in resp.data
    assert client.get('/api/pie').status_code == 401


def test_self_registration_blocked_when_disabled(flask_app, client, make_user):
    make_user('existing_admin', role='admin')
    flask_app.config['ALLOW_SELF_REGISTRATION'] = False
    try:
        resp = client.post('/auth/register', data={
            'username': 'intruder', 'email': 'i@example.test',
            'password': 'Password-123', 'confirm_password': 'Password-123'})
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith('/auth/login')
        assert AuthManager.user_count() >= 1
    finally:
        flask_app.config['ALLOW_SELF_REGISTRATION'] = True


def test_password_is_stored_hashed(make_user):
    from src.threat_classifier.database.connection import db
    from src.threat_classifier.database.models import User
    user, pw = make_user('hash_check')
    s = db.get_session()
    try:
        row = s.query(User).filter_by(username=user).one()
        assert row.password_hash != pw
        assert row.check_password(pw)
    finally:
        s.close()
