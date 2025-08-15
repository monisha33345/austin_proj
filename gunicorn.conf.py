# gunicorn.conf.py
import os

bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"  # Render provides PORT
workers = int(os.getenv("WEB_CONCURRENCY", "2"))  # 1–2 on free tier to save RAM
threads = int(os.getenv("THREADS", "2"))
timeout = int(os.getenv("TIMEOUT", "120"))
keepalive = 5
graceful_timeout = 30
accesslog = "-"   # log to stdout
errorlog = "-"    # log to stdout
