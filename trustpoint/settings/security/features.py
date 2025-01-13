from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod

from pki.auto_gen_pki import AutoGenPki
from pki.management.commands.base_commands import CertificateCreationCommandMixin
from pki.models import DomainModel, IssuingCaModel
from util.keys import KeyGenerator, SignatureSuite
from settings.models import SecurityConfig


class SecurityFeature(ABC):
    """Abstract base class for a security feature."""

    verbose_name = None
    db_field_name = None

    @abstractmethod
    def enable(self, *args) -> None:
        """Enables the feature."""
        pass

    @abstractmethod
    def disable(self, *args) -> None:
        """Disables the feature."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Returns True if the feature is currently enabled."""
        pass


class AutoGenPkiFeature(SecurityFeature):
    """Manages the auto-generated local CAs (PKI)."""

    verbose_name = 'Local Auto-Generated PKI'
    db_field_name = 'auto_gen_pki'

    @staticmethod
    def is_enabled():
        return SecurityConfig.objects.first().auto_gen_pki

    @staticmethod
    def enable(key_alg: SignatureSuite) -> None:
        """Starts a thread that enables the auto-generated PKI.Pass thread arguments as a tuple to avoid any issues."""
        if __class__.is_enabled():
            thread = threading.Thread(
                target=AutoGenPki.enable_auto_gen_pki,
                args=(key_alg,)
            )
            thread.start()

    @staticmethod
    def disable() -> None:
        """Starts a thread that disables the auto-generated PKI."""
        thread = threading.Thread(
            target=AutoGenPki.disable_auto_gen_pki
        )
        thread.start()

        conf = SecurityConfig.objects.first()
        conf.auto_gen_pki = False
        conf.save()
