from __future__ import annotations

import logging

log = logging.getLogger('tp.pki')

class AutoGenPki:
    """Manages the auto-generated local CAs."""

    @staticmethod
    def enable_auto_gen_pki() -> None:
        """Enables the auto-generated PKI."""
        log.warning('! Enabling auto-generated PKI !')
        pass
    
    @staticmethod
    def disable_auto_gen_pki() -> None:
        """Disables the auto-generated PKI."""
        log.warning('! Disabling auto-generated PKI !')
        pass