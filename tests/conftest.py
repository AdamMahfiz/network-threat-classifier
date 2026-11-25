"""
Test setup. Environment variables are set before `app` is imported, because the
app builds its configuration and database connection at import time.
Tests use a throw-away SQLite file, never the committed data/threat_classifier.db.
"""

import os
import sys
import tempfile
import uuid

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, REPO_ROOT)

_TEST_DIR = tempfile.mkdtemp(prefix='ntc-tests-')
os.environ.update({
    'APP_ENV': 'testing',
    'SECRET_KEY': 'test-secret-key-that-is-long-enough-for-prod-rules-1234',
    'SQLITE_DATABASE_PATH': os.path.join(_TEST_DIR, 'test.db'),
    'ALLOW_SELF_REGISTRATION': 'true',
    'ENABLE_TEST_ROUTES': 'true',
    'LOGIN_MAX_FAILURES': '3',
    'LOGIN_LOCKOUT_MINUTES': '15',
})
os.chdir(REPO_ROOT)

import app as app_module  # noqa: E402
from src.threat_classifier.auth.auth_manager import AuthManager, login_throttle  # noqa: E402


@pytest.fixture
def flask_app():
    app_module.app.config.update(TESTING=True)
    yield app_module.app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def make_user():
    """Create a user directly through the auth layer. Returns (username, password)."""
    created = []

    def _make(username, password='CorrectHorse-9', role='user'):
        # Suffix keeps names unique: the test database persists across the run.
        username = f"{username}_{uuid.uuid4().hex[:8]}"
        ok, msg = AuthManager.register_user(
            username, f'{username}@example.test', password, 'Test', 'User', role=role
        )
        assert ok, msg
        created.append(username)
        return username, password

    yield _make


@pytest.fixture(autouse=True)
def reset_login_throttle():
    login_throttle._failures.clear()
    login_throttle._locked_until.clear()
    yield
    login_throttle._failures.clear()
    login_throttle._locked_until.clear()


def login(client, username, password):
    return client.post('/auth/login', data={'username': username, 'password': password},
                       follow_redirects=False)
