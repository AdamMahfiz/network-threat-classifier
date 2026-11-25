"""
Central configuration for Network Threat Classifier 2.0.

All settings come from environment variables (or a .env file). The app reads
them once through `load_config()` so behaviour is explicit and testable.

APP_ENV:
  development  - debug tools allowed, relaxed defaults, a dev-only SECRET_KEY is generated
  testing      - used by the test suite
  production   - strict: SECRET_KEY is mandatory, debug is forced off,
                 self-registration is off unless explicitly enabled
"""

import os
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

from dotenv import load_dotenv

load_dotenv()

APP_VERSION = '2.0.0'

_TRUE = {'1', 'true', 'yes', 'on'}


def _env_bool(env, name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == '':
        return default
    return raw.strip().lower() in _TRUE


def _env_list(env, name: str) -> List[str]:
    raw = env.get(name, '')
    return [item.strip() for item in raw.split(',') if item.strip()]


class ConfigError(RuntimeError):
    """Raised when configuration is unsafe or incomplete for the chosen environment."""


@dataclass
class Config:
    app_env: str = 'development'
    version: str = APP_VERSION
    secret_key: str = ''
    debug: bool = False

    database_url: str = ''
    sqlite_path: str = 'data/threat_classifier.db'

    cors_origins: List[str] = field(default_factory=list)
    socketio_async_mode: str = 'threading'

    session_timeout_minutes: int = 30
    allow_self_registration: bool = False
    enable_test_routes: bool = False

    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    upload_max_mb: int = 100
    port: int = 5000

    @property
    def is_production(self) -> bool:
        return self.app_env == 'production'

    @property
    def session_lifetime(self) -> timedelta:
        return timedelta(minutes=self.session_timeout_minutes)


def load_config(env: dict = None) -> Config:
    """Build a Config from the environment and validate it."""
    env = os.environ if env is None else env

    def get(name, default=''):
        value = env.get(name)
        return default if value is None or value == '' else value

    app_env = get('APP_ENV', 'development').lower()
    if app_env not in {'development', 'testing', 'production'}:
        raise ConfigError(f"APP_ENV must be development, testing or production, got '{app_env}'")

    is_prod = app_env == 'production'

    secret_key = get('SECRET_KEY', '')
    if not secret_key:
        if is_prod:
            raise ConfigError('SECRET_KEY must be set when APP_ENV=production')
        # Random per process: sessions reset on restart, but no shared known key.
        secret_key = secrets.token_urlsafe(48)
    elif is_prod and len(secret_key) < 32:
        raise ConfigError('SECRET_KEY must be at least 32 characters in production')

    cfg = Config(
        app_env=app_env,
        secret_key=secret_key,
        debug=_env_bool(env, 'FLASK_DEBUG', False) and not is_prod,
        database_url=get('DATABASE_URL', ''),
        sqlite_path=get('SQLITE_DATABASE_PATH', 'data/threat_classifier.db'),
        cors_origins=_env_list(env, 'CORS_ORIGINS'),
        socketio_async_mode=get('SOCKETIO_ASYNC_MODE', 'threading'),
        session_timeout_minutes=int(get('SESSION_TIMEOUT_MINUTES', '30')),
        allow_self_registration=_env_bool(env, 'ALLOW_SELF_REGISTRATION', not is_prod),
        enable_test_routes=_env_bool(env, 'ENABLE_TEST_ROUTES', False) and not is_prod,
        login_max_failures=int(get('LOGIN_MAX_FAILURES', '5')),
        login_lockout_minutes=int(get('LOGIN_LOCKOUT_MINUTES', '15')),
        upload_max_mb=int(get('UPLOAD_MAX_MB', '100')),
        port=int(get('PORT', '5000')),
    )

    if cfg.socketio_async_mode not in {'threading', 'eventlet'}:
        raise ConfigError("SOCKETIO_ASYNC_MODE must be 'threading' or 'eventlet'")
    if is_prod and '*' in cfg.cors_origins:
        raise ConfigError("CORS_ORIGINS may not contain '*' in production")

    return cfg


CONFIG = None


def get_config() -> Config:
    """Return the process-wide config, loading it on first use."""
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()
    return CONFIG
