"""Tests for the log application."""

import logging
import time
from django.test import TestCase

test_log = logging.getLogger('tp.test')

class LogTestCase(TestCase):
    """Tests for the log application."""
    def test_log_format(self):
        """Test that log entries are written to disk in time and formatted correctly."""
        test_log.debug('Unit Test log entry')
        # wait for the file system
        time.sleep(0.5)
        with open('tp.log', 'r') as log_file:
            log_entry = log_file.readlines()[-1]
            self.assertRegex(log_entry,
                r'2\d{3}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} tp.test DEBUG Unit Test log entry\n')
