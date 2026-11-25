from tests.conftest import login


def _signed_in(client, make_user):
    user, pw = make_user('api_user')
    login(client, user, pw)
    return client


def test_classify_rejects_non_string_logs(client, make_user):
    c = _signed_in(client, make_user)
    resp = c.post('/api/classify', json={'logs': ['not', 'a', 'string']})
    assert resp.status_code == 400
    assert 'must be a string' in resp.get_json()['error']


def test_classify_rejects_missing_logs(client, make_user):
    c = _signed_in(client, make_user)
    assert c.post('/api/classify', json={}).status_code == 400


def test_classify_returns_results_for_text(client, make_user):
    c = _signed_in(client, make_user)
    resp = c.post('/api/classify', json={'logs': 'Failed password for root from 10.0.0.5 port 22\nUser login ok'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
