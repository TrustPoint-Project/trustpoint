from __future__ import annotations

import logging

from pki.models import IssuingCaModel

from sysconf.security import SecurityFeatures
from sysconf.security.decorators import security_level

log = logging.getLogger('tp.pki')

class AutoGenPki:
    """Manages the auto-generated local CAs."""

    @staticmethod
    @security_level(SecurityFeatures.AUTO_GEN_PKI)
    def enable_auto_gen_pki() -> None:
        """Enables the auto-generated PKI."""
        log.warning('! Enabling auto-generated PKI !')

        # check if local root CA exists
        try:
            root_ca = IssuingCaModel.objects.get(unique_name='local_auto_gen_pki_root_ca')
            log.info('Using existing local auto-generated PKI Root CA')
        except IssuingCaModel.DoesNotExist:
            log.info('Creating local auto-generated PKI Root CA')
            root_ca = IssuingCaModel()
            root_ca.unique_name = 'local_auto_gen_pki_root_ca'
            root_ca.save()

        pass
    
    @staticmethod
    def disable_auto_gen_pki() -> None:
        """Disables the auto-generated PKI."""
        log.warning('! Disabling auto-generated PKI !')
        pass