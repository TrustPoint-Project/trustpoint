from __future__ import annotations

import abc
import logging

from . import IssuingCaInitializer
from . import IssuingCaInitializerError

from pki.util.keys import KeyAlgorithm, KeyGenerator

class KeyGenLocalIssuingCaInitializer(IssuingCaInitializer, abc.ABC):
    """Abstract base class for the key generation local issuing CA initializer."""
    _unique_name: str
    _auto_crl: bool

    _is_initialized: bool = False

class UnprotectedKeyGenLocalIssuingCaInitializer(KeyGenLocalIssuingCaInitializer):
    
    def __init__(self, unique_name: str, key_algorithm: KeyAlgorithm, auto_crl: bool = True) -> None:
        self._unique_name = unique_name
        self._auto_crl = auto_crl
        self._is_initialized = False

    def initialize(self) -> None:
        """Initializes the key generation local issuing CA."""

        self._private_key = KeyGenerator(self._key_algorithm).generate_key()

        self._is_initialized = True