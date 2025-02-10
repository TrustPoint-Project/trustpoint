"""Manages the auto-generated local PKI."""

from __future__ import annotations

import logging
import threading

from pki.management.commands.base_commands import CertificateCreationCommandMixin
from pki.models import DomainModel, IssuingCaModel
from pki.util.keys import AutoGenPkiKeyAlgorithm, KeyGenerator

log = logging.getLogger('tp.pki')
UNIQUE_NAME = 'AutoGenPKI_Issuing_CA'


class AutoGenPki:
    """Handles enabling and disabling of auto-generated PKI."""

    _lock: threading.Lock = threading.Lock()

    @classmethod
    def get_auto_gen_pki(cls) -> IssuingCaModel | None:
        """Retrieves the auto-generated PKI Issuing CA, if it exists."""
        try:
            return IssuingCaModel.objects.get(unique_name=UNIQUE_NAME)
        except IssuingCaModel.DoesNotExist:
            return None

    @classmethod
    def enable_auto_gen_pki(cls, key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Enables the auto-generated PKI."""
        with cls._lock:
            log.warning('! Enabling auto-generated PKI !')

            auto_pki = cls.get_auto_gen_pki()

            if not auto_pki:
                root_ca_name = f'AutoGenPKI_Root_CA_{key_alg}'
                public_key_info = key_alg.to_public_key_info()
                key_gen = KeyGenerator()

                # Create root and issuing CAs
                root_1, root_1_key = CertificateCreationCommandMixin.create_root_ca(
                    root_ca_name, private_key=key_gen.generate_private_key_for_public_key_info(public_key_info)
                )
                issuing_1, issuing_1_key = CertificateCreationCommandMixin.create_issuing_ca(
                    root_1_key,
                    root_ca_name,
                    UNIQUE_NAME,
                    private_key=key_gen.generate_private_key_for_public_key_info(public_key_info),
                    validity_days=50,
                )

                # Save issuing CA
                issuing_ca = CertificateCreationCommandMixin.save_issuing_ca(
                    root_ca_cert=root_1,
                    issuing_ca_cert=issuing_1,
                    private_key=issuing_1_key,
                    chain=[],
                    unique_name=UNIQUE_NAME,
                )

                # Link to domain
                DomainModel.objects.get_or_create(
                    unique_name='AutoGenPKI',
                    defaults={'issuing_ca': issuing_ca},
                )

            log.warning('Auto-generated PKI enabled.')

    @classmethod
    def disable_auto_gen_pki(cls) -> None:
        """Disables the auto-generated PKI."""
        with cls._lock:
            issuing_ca = cls.get_auto_gen_pki()
            if not issuing_ca:
                log.error(
                    'Issuing CA for auto-generated PKI does not exist - '
                    'auto-generated PKI possibly not fully disabled'
                )
                return

            log.warning('! Disabling auto-generated PKI !')
            issuing_ca.delete()
            log.warning('Auto-generated PKI disabled.')
