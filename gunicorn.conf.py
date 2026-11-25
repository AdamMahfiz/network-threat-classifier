import os

# Socket.IO needs sticky, in-process state (login throttle, socket sessions),
# so run a single worker with eventlet green threads.
worker_class = "eventlet"
workers = 1
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
timeout = 120
accesslog = "-"
errorlog = "-"
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
