"""Global logging utilities and configuration."""

import logging
import os
from pathlib import Path

from log.utils import UTCFormatter

BASE_PATH = Path(__file__).parent.parent

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filename': BASE_PATH / Path('media/log/tp.log'),
            'when': 'midnight',
            'interval': 1,
            'backupCount': 365,  # Keep at least a year of logs
            'utc': True,
            'delay': True # This fixes PermissionError on log rotation in windows
        },
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'detailed',
        },
    },
    'formatters': {
        'detailed': {
            '()': UTCFormatter,
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'root': {
            'level': 'INFO',
            'handlers': ['file'],
        },
        'tp': {
            'level': 'INFO',
            'handlers': ['file', 'console'],
            'propagate': False,
        },
    }
}
