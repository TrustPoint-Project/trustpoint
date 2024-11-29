"""Manages the auto-generated local PKI."""
# ruff: noqa: TRY400

from __future__ import annotations

import logging
import threading

from settings.security import SecurityFeatures
from settings.security.decorators import security_level

from pki.initializer.issuing_ca.key_gen import (
    UnprotectedKeyGenLocalIssuingCaInitializer,
    UnprotectedKeyGenLocalRootCaInitializer,
)
from pki.models import DomainModel, IssuingCaModel, ReasonCode, RootCaModel
from pki.util.keys import AutoGenPkiKeyAlgorithm

log = logging.getLogger('tp.pki')

class AutoGenPki:
    """Manages the auto-generated local CAs."""
    _lock : threading.Lock = threading.Lock() # prevent concurrent enable/disable

    @staticmethod
    @security_level(SecurityFeatures.AUTO_GEN_PKI)
    def enable_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Starts a thread that enables the auto-generated PKI."""
        thread = threading.Thread(target=AutoGenPki._enable_auto_gen_pki, args=(key_alg,))
        thread.start()

    @staticmethod
    def disable_auto_gen_pki() -> None:
        """Starts a thread that disables the auto-generated PKI."""
        thread = threading.Thread(target=AutoGenPki._disable_auto_gen_pki)
        thread.start()

    @staticmethod
    @security_level(SecurityFeatures.AUTO_GEN_PKI)
    def _enable_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Enables the auto-generated PKI."""
        AutoGenPki._lock.acquire()
        log.warning('! Enabling auto-generated PKI !')

        key_algorithm = AutoGenPkiKeyAlgorithm.to_key_algorithm(key_alg)
        root_ca_name = 'AutoGenPKI_Root_CA_%s' % key_algorithm.value

        # check if local root CA exists
        try:
            _ = RootCaModel.objects.get(unique_name=root_ca_name)
            log.info('Using existing local auto-generated PKI Root CA')
        except RootCaModel.DoesNotExist:
            log.info('Creating local auto-generated PKI Root CA')
            root_ca_initializer = UnprotectedKeyGenLocalRootCaInitializer(root_ca_name, key_algorithm, auto_crl=True)
            root_ca_initializer.initialize()
            root_ca_initializer.save()

        try:
            root_ca = RootCaModel.objects.get(unique_name=root_ca_name)
        except RootCaModel.DoesNotExist:
            log.error('Local auto-generated PKI Root CA is not in database - illegal state')
            raise

        # check if local issuing CA exists (it shouldn't as it is deleted on auto-gen PKI disable)
        try:
            _ = IssuingCaModel.objects.get(unique_name='AutoGenPKI_Issuing_CA')
            log.error('Local auto-generated PKI Issuing CA already exists - illegal re-enable of auto-gen PKI?')
        except IssuingCaModel.DoesNotExist:
            log.info('Creating local auto-generated PKI Issuing CA')
            root_ca_instance = root_ca.get_issuing_ca()
            issuing_ca_initializer = UnprotectedKeyGenLocalIssuingCaInitializer(
                'AutoGenPKI_Issuing_CA', key_algorithm, root_ca = root_ca_instance, auto_crl=True)
            issuing_ca_initializer.initialize()
            issuing_ca_initializer.save()

        try:
            issuing_ca = IssuingCaModel.objects.get(unique_name='AutoGenPKI_Issuing_CA')
        except IssuingCaModel.DoesNotExist:
            log.error('Local auto-generated PKI Issuing CA is not in database - illegal state')
            raise

        # for convenience, also generate a domain
        try:
            _ = DomainModel.objects.get(unique_name='AutoGenPKI')
        except DomainModel.DoesNotExist:
            domain = DomainModel(unique_name='AutoGenPKI')
            domain.issuing_ca = issuing_ca
            domain.save()

        log.warning('Auto-generated PKI enabled.')
        AutoGenPki._lock.release()

    @staticmethod
    def _disable_auto_gen_pki() -> None:
        """Disables the auto-generated PKI."""
        AutoGenPki._lock.acquire()
        log.warning('! Disabling auto-generated PKI !')
        try:
            issuing_ca = IssuingCaModel.objects.get(unique_name='AutoGenPKI_Issuing_CA')
        except IssuingCaModel.DoesNotExist:
            log.error('Issuing CA for auto-generated PKI does not exist - '
                      'auto-generated PKI possibly not fully disabled')
            AutoGenPki._lock.release()
            return

        issuing_ca_instance = issuing_ca.get_issuing_ca()
        issuing_ca_instance.revoke_all_certificates()
        issuing_ca_instance.get_issuing_ca_certificate().revoke(revocation_reason=ReasonCode.CESSATION)
        issuing_ca.delete()
        log.warning('Auto-generated PKI disabled.')
        AutoGenPki._lock.release()
