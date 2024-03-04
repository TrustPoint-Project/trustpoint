"""Contains utility functions for string manipulation and validation"""

import re


class StringValidator:
    """Contains utility functions for string validation"""

    @staticmethod
    def is_urlsafe(string: str) -> bool:
        """Returns True if string only contains alphanumeric characters and '-' or '_'"""
        p = re.compile(r'[^a-zA-Z0-9\-_]')
        return (p.search(string) is None)
