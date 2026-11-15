import ssl
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings


def _clean_redis_url(url: str) -> str:
    if not url:
        return url
    cleaned = url.strip()
    while cleaned.endswith("//"):
        cleaned = cleaned[:-1]
    return cleaned


broker_url = _clean_redis_url(settings.CELERY_BROKER_URL)
backend_url = _clean_redis_url(settings.CELERY_RESULT_BACKEND)

celery_app = Celery(
    "traceops",
    broker=broker_url,
    backend=backend_url,
    include=["app.tasks.celery_tasks"],
)

conf_dict = {
    "task_serializer": "json",
    "accept_content": ["json"],
    "result_serializer": "json",
    "timezone": "UTC",
    "enable_utc": True,
    "task_track_started": True,
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "broker_connection_retry_on_startup": True,
    "broker_connection_max_retries": 10,
    "beat_schedule": {
        "daily-audit-report": {
            "task": "app.tasks.celery_tasks.generate_daily_report",
            "schedule": crontab(hour=22, minute=0),  # 10 PM UTC daily
        },
        "fetch-git-events": {
            "task": "app.tasks.celery_tasks.fetch_git_events",
            "schedule": crontab(minute="*/30"),  # every 30 min
        },
    },
}

# SSL configuration for cloud Redis (Upstash, Render, AWS ElastiCache)
if broker_url.startswith("rediss://"):
    conf_dict["broker_use_ssl"] = {"ssl_cert_reqs": ssl.CERT_NONE}

if backend_url.startswith("rediss://"):
    conf_dict["redis_backend_use_ssl"] = {"ssl_cert_reqs": ssl.CERT_NONE}

celery_app.conf.update(conf_dict)
