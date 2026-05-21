# Gunicorn configuration for ForensicTool
bind = "127.0.0.1:8000"
workers = 3
worker_class = "sync"
timeout = 300          # long timeout for disk image processing
keepalive = 5
accesslog = "/home/trezman/FYP/forensic_tool/logs/gunicorn_access.log"
errorlog  = "/home/trezman/FYP/forensic_tool/logs/gunicorn_error.log"
loglevel  = "info"
