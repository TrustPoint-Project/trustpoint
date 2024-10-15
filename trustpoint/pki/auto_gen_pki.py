from __future__ import annotations

import logging

from pki.models import IssuingCaModel
from pki.initializer.issuing_ca.key_gen import UnprotectedKeyGenLocalRootCaInitializer, UnprotectedKeyGenLocalIssuingCaInitializer
from pki.util.keys import KeyAlgorithm

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

        key_algorithm = KeyAlgorithm.RSA4096

        # check if local root CA exists
        try:
            root_ca = IssuingCaModel.objects.get(unique_name='local_auto_gen_pki_root_ca')
            log.info('Using existing local auto-generated PKI Root CA')
        except IssuingCaModel.DoesNotExist:
            log.info('Creating local auto-generated PKI Root CA')
            root_ca_initializer = UnprotectedKeyGenLocalRootCaInitializer('local_auto_gen_pki_root_ca', key_algorithm, auto_crl=True)
            root_ca_initializer.initialize()
            root_ca_initializer.save()

        try:
            root_ca = IssuingCaModel.objects.get(unique_name='local_auto_gen_pki_root_ca')
            log.info('Using existing local auto-generated PKI Root CA')
        except IssuingCaModel.DoesNotExist:
            log.error('Local auto-generated PKI Root CA is not in database - illegal state')
            raise
            

        # check if local issuing CA exists (it shouldn't as it is deleted on auto-gen PKI disable)
        try:
            issuing_ca = IssuingCaModel.objects.get(unique_name='local_auto_gen_pki_issuing_ca')
            log.error('Local auto-generated PKI Issuing CA already exists - illegal re-enable of auto-gen PKI?')
        except IssuingCaModel.DoesNotExist:
            log.info('Creating local auto-generated PKI Issuing CA')
            root_ca_instance = root_ca.get_issuing_ca()
            issuing_ca_initializer = UnprotectedKeyGenLocalIssuingCaInitializer('local_auto_gen_pki_issuing_ca', key_algorithm, root_ca = root_ca_instance, auto_crl=True)
            issuing_ca_initializer.initialize()
            issuing_ca_initializer.save()
        pass
    
    @staticmethod
    def disable_auto_gen_pki() -> None:
        """Disables the auto-generated PKI."""
        log.warning('! Disabling auto-generated PKI !')
        pass