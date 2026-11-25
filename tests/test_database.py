from src.threat_classifier.database.connection import db
from tests.conftest import login


def test_database_info_reports_connected():
    info = db.get_database_info()
    assert info['status'] == 'connected', info
    assert info['type'] == db.engine.dialect.name


def test_database_url_never_shows_password():
    info = db.get_database_info()
    assert '***' in info['url'] or ':' not in info['url'].split('://', 1)[-1].split('@')[0]


def test_db_health_endpoint_works_for_admin(client, make_user):
    user, pw = make_user('dbadmin', role='admin')
    login(client, user, pw)
    resp = client.get('/api/db_health')
    assert resp.status_code == 200, resp.get_data(as_text=True)
