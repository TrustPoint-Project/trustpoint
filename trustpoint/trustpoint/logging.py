"""Global logging utilities and configuration."""

import logging
import os
from datetime import datetime, timezone
import time

class UTCFormatter(logging.Formatter):
    converter = time.gmtime  # Use gmtime for UTC conversion

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = datetime.fromtimestamp(record.created, tz=timezone.utc)
            t = t.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s.%03d" % (t, record.msecs)
        return s

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': 'tp.log',
            'when': 'midnight',
            'interval': 1,
            'backupCount': 365,  # Keep at least a year of logs
            'utc': True,
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