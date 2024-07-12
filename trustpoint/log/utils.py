"""Logging-specific utilities."""

import logging
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
