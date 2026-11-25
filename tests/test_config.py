import pytest

from config import ConfigError, load_config

STRONG = 'x' * 40


def test_production_requires_secret_key():
    with pytest.raises(ConfigError, match='SECRET_KEY must be set'):
        load_config({'APP_ENV': 'production'})


def test_production_rejects_short_secret_key():
    with pytest.raises(ConfigError, match='at least 32'):
        load_config({'APP_ENV': 'production', 'SECRET_KEY': 'short'})


def test_production_forces_safe_defaults():
    cfg = load_config({'APP_ENV': 'production', 'SECRET_KEY': STRONG,
                       'FLASK_DEBUG': 'True', 'ENABLE_TEST_ROUTES': 'true',
                       'ALLOW_SELF_REGISTRATION': 'true'})
    assert cfg.debug is False
    assert cfg.enable_test_routes is False
    # Self-registration is an explicit opt-in even when set, production still honours the flag
    assert cfg.allow_self_registration is True


def test_production_registration_off_by_default():
    cfg = load_config({'APP_ENV': 'production', 'SECRET_KEY': STRONG})
    assert cfg.allow_self_registration is False


def test_production_rejects_wildcard_cors():
    with pytest.raises(ConfigError, match='may not contain'):
        load_config({'APP_ENV': 'production', 'SECRET_KEY': STRONG, 'CORS_ORIGINS': '*'})


def test_development_generates_random_key_when_missing():
    a = load_config({'APP_ENV': 'development'})
    b = load_config({'APP_ENV': 'development'})
    assert a.secret_key and b.secret_key and a.secret_key != b.secret_key
    assert a.secret_key != 'dev-secret-key'


def test_cors_origins_parsed():
    cfg = load_config({'APP_ENV': 'development', 'CORS_ORIGINS': 'https://a.example, https://b.example'})
    assert cfg.cors_origins == ['https://a.example', 'https://b.example']


def test_invalid_env_rejected():
    with pytest.raises(ConfigError):
        load_config({'APP_ENV': 'staging'})
