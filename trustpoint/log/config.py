"""Global logging utilities and configuration."""

import os

from log.utils import UTCFormatter
from pathlib import Path

LOG_PATH = Path(__file__).parent.parent / Path('media/log/tp.log')

if not LOG_PATH.exists():
    LOG_PATH.open('w').write('')

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': str(LOG_PATH),
            'when': 'midnight',
            'interval': 1,
            'backupCount': 365,  # Keep at least a year of logs
            'utc': True,
            'delay': True # This fixes PermissionError on log rotation in windows
        },
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
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
            'level': 'WARNING',
            'handlers': ['file'],
        },
        'tp': {
            'level': 'DEBUG',
            'handlers': ['file', 'console'],
            'propagate': False,
        },
    }
}
