from __future__ import annotations

import abc
import datetime

from pki.issuing_ca import UnprotectedLocalIssuingCa
from pki.models import RootCaModel
from pki.serializer import CertificateCollectionSerializer
from pki.util.ca import CaGenerator
from pki.util.keys import KeyAlgorithm, KeyGenerator

from .local import LocalIssuingCaInitializer

ONE_DAY = datetime.timedelta(1, 0, 0)

class KeyGenLocalIssuingCaInitializer(LocalIssuingCaInitializer, abc.ABC):
    """Abstract base class for the key generation local issuing CA initializer."""

class UnprotectedKeyGenLocalCaInitializer(KeyGenLocalIssuingCaInitializer):
    """Base class for unprotected local CA initializers."""
    _key_algorithm: KeyAlgorithm

    def __init__(self, unique_name: str, key_algorithm: KeyAlgorithm, auto_crl: bool = True) -> None:
        self._unique_name = unique_name
        self._auto_crl = auto_crl
        self._key_algorithm = key_algorithm
        self._is_initialized = False

class UnprotectedKeyGenLocalRootCaInitializer(UnprotectedKeyGenLocalCaInitializer):
    """Responsible for initializing the local root CA."""
    _issuing_ca_model_class : type[RootCaModel] = RootCaModel # overriding IssuingCaModel

    def initialize(self) -> None:
        """Initializes the local root CA."""
        self._private_key = KeyGenerator(self._key_algorithm).generate_key()

        subject_ = CaGenerator.generate_subject('trustpoint.auto_gen_pki.%s.root' %  self._key_algorithm.value.lower())

        not_valid_before = datetime.datetime.today() - ONE_DAY
        not_valid_after = datetime.datetime.today() + ONE_DAY * 365 * 10

        certificate = CaGenerator.generate_ca_certificate(subject_=subject_,
                                                          issuer_=subject_,
                                                          subject_key=self._private_key.public_key(),
                                                          signing_key=self._private_key,
                                                          not_valid_before=not_valid_before,
                                                          not_valid_after=not_valid_after)

        self._credential_serializer = self._credential_serializer_class(
            (self._private_key,certificate)
        )

        self._is_initialized = True

class UnprotectedKeyGenLocalIssuingCaInitializer(UnprotectedKeyGenLocalCaInitializer):
    """Responsible for initializing the local issuing (subordinate) CA."""
    _root_ca: UnprotectedLocalIssuingCa

    def __init__(self, unique_name: str, key_algorithm: KeyAlgorithm,
                 root_ca: UnprotectedLocalIssuingCa, auto_crl: bool = True) -> None:
        """Initialize the arguments."""
        self._unique_name = unique_name
        self._auto_crl = auto_crl
        self._key_algorithm = key_algorithm
        self._is_initialized = False
        self._root_ca = root_ca

    def initialize(self) -> None:
        """Initializes the local issuing CA."""
        self._private_key = KeyGenerator(self._key_algorithm).generate_key()

        subject_ = CaGenerator.generate_subject('trustpoint.auto_gen_pki.issuing')

        not_valid_before = datetime.datetime.today() - ONE_DAY
        not_valid_after = datetime.datetime.today() + ONE_DAY * 365 * 10

        root_subject = self._root_ca.subject_name
        root_private_key = self._root_ca.private_key
        root_certificate = self._root_ca.get_issuing_ca_certificate().get_certificate_serializer()

        certificate = CaGenerator.generate_ca_certificate(subject_=subject_,
                                                          issuer_=root_subject,
                                                          subject_key=self._private_key.public_key(),
                                                          signing_key=root_private_key,
                                                          not_valid_before=not_valid_before,
                                                          not_valid_after=not_valid_after)

        self._credential_serializer = self._credential_serializer_class(
            (self._private_key,certificate, CertificateCollectionSerializer([root_certificate]))
        )

        self._is_initialized = True
