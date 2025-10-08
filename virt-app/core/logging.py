import logging
from logging.config import dictConfig

from .config import LOG_LEVEL, APP_NAME
from .log_stream import log_stream_handler

def setup_logging():
    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s %(levelname)s %(name)s - %(message)s"
            },
            "uvicorn": {
                "format": "%(asctime)s %(levelname)s uvicorn %(name)s - %(message)s"
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
            },
        },
        "loggers": {
            "": {"handlers": ["console"], "level": LOG_LEVEL},
            "uvicorn": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
            "uvicorn.error": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
            "uvicorn.access": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
            APP_NAME: {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        },
    })
    logging.getLogger(APP_NAME).info("Logging initialized at level %s", LOG_LEVEL)
    logging.getLogger().addHandler(log_stream_handler)

