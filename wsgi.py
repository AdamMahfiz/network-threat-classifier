"""Production entry point. Run with: gunicorn -c gunicorn.conf.py wsgi:app

eventlet must patch the standard library before anything else is imported,
otherwise Socket.IO and blocking I/O can misbehave under gunicorn.
"""
import eventlet
eventlet.monkey_patch()

from app import app, socketio  # noqa: E402,F401
