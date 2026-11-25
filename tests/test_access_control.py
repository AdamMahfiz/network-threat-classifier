import pytest

from tests.conftest import login

# Every API/data route must refuse anonymous callers (2.0 access control).
PROTECTED = [
    ('POST', '/api/classify'), ('POST', '/api/upload'),
    ('GET', '/api/audit/sessions'), ('GET', '/api/audit/session/abc'),
    ('GET', '/api/pie'), ('GET', '/api/trends'), ('GET', '/api/alerts'),
    ('GET', '/audit'), ('GET', '/download_report'), ('GET', '/monitor'),
    ('GET', '/api/db_health'), ('POST', '/api/db_cleanup'),
    ('POST', '/api/test-alert'), ('POST', '/api/test-email-alert'),
    ('GET', '/db_health'), ('GET', '/'),
]


@pytest.mark.parametrize('method,path', PROTECTED)
def test_anonymous_requests_are_refused(client, method, path):
    resp = client.open(path, method=method)
    assert resp.status_code in (401, 302), (path, resp.status_code)
    assert resp.status_code != 200


def test_api_returns_json_401_for_anonymous(client):
    resp = client.get('/api/pie')
    assert resp.status_code == 401
    assert resp.get_json() == {'error': 'Authentication required'}


@pytest.mark.parametrize('path', ['/test-monitor', '/test-monitor/start',
                                  '/test-monitor/status', '/test-monitor/stop'])
def test_test_routes_hidden_when_disabled(flask_app, client, path):
    from config import get_config
    cfg = get_config()
    previous = cfg.enable_test_routes
    cfg.enable_test_routes = False
    try:
        assert client.open(path, method='POST' if path.endswith(('start', 'stop')) else 'GET').status_code == 404
    finally:
        cfg.enable_test_routes = previous


def test_health_is_public_and_reports_version(client):
    resp = client.get('/health')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['status'] == 'healthy'
    assert body['version'] == '2.0.0'


def test_security_headers_present(client):
    resp = client.get('/health')
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert 'Referrer-Policy' in resp.headers


def test_non_admin_cannot_reach_admin_api(client, make_user):
    user, pw = make_user('plain_user', role='user')
    login(client, user, pw)
    resp = client.post('/api/db_cleanup')
    assert resp.status_code == 403
    assert resp.get_json() == {'error': 'Administrator role required'}
