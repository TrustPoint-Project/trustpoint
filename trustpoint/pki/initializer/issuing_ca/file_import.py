from __future__ import annotations

import abc
import logging

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

from pki.serializer import (
    PrivateKeySerializer,
    CertificateCollectionSerializer,
    CredentialSerializer
)

from . import IssuingCaInitializer
from . import IssuingCaInitializerError
from .local import LocalIssuingCaInitializer
from .local import LocalIssuingCaInitializerError, InternalServerError, IssuingCaAlreadyExistsError

from pki.util import Sha256Fingerprint, CredentialExtractor

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]

log = logging.getLogger('tp.pki.initializer')


class FileImportLocalIssuingCaInitializerError(LocalIssuingCaInitializerError):
    """Base class for file import local issuing CA initializer errors."""	
    pass


class FileSerializationError(FileImportLocalIssuingCaInitializerError):
    """Raised if the serialization of the uploaded file(s) failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message)


class TooManyCertificatesError(FileImportLocalIssuingCaInitializerError):
    """Raised if too many certificates were uploaded."""

    def __init__(self, cert_count: int, limit: int) -> None:
        super().__init__(message=_(
            f'The uploaded file(s) contain more than {cert_count} certificates. '
            f'Refusing to process more than {limit} certificates.'))


class FileImportLocalIssuingCaInitializer(LocalIssuingCaInitializer, abc.ABC):
    """Base class for importing a new Issuing CA through a file upload(s)."""

    _CERTIFICATE_UPLOAD_FILE_LIMIT: int = 100

    _password: None | bytes

    @abc.abstractmethod
    def _serialize_raw_data(self) -> None:
        pass

    @property
    def password(self) -> None | bytes:
        """Returns the password for the credential (PKCS#12) or private key."""
        return self._password

    @password.setter
    def password(self, password: None | bytes) -> None:
        """Sets the password and implicitly changes empty bytes to None."""
        if password == b'':
            password = None
        self._password = password

    def _check_certificate_upload_file_limit(self) -> None:
        cert_count = len(self._certificate_collection_serializer)
        if cert_count > self._CERTIFICATE_UPLOAD_FILE_LIMIT:
            raise TooManyCertificatesError(
                cert_count=cert_count,
                limit=self._CERTIFICATE_UPLOAD_FILE_LIMIT
            )

    def initialize(self) -> None:
        """Tries to initialize uploaded file(s).

        Raises:
            FileSerializationError: If the serialization of the uploaded file(s) failed.
            TooManyCertificatesError: If there were too many certificates uploaded.
            MissingIssuingCaCertificate: If no Issuing CA certificate was found.
            IncompleteCertificateChainError: If no complete certificate chain was found.
            MultipleIssuingCaCertificatesFoundError: If multiple Issuing CAs were found.
            MultipleCertificateChainsFoundError: If multiple certificate chains were found.
            CertificateChainContainsCycleError: If the certificate chain contains a cycle (graph).
        """
        try:
            self._serialize_raw_data()
        except (ValueError, TypeError) as exception:
            raise ValidationError(str(exception))
        self._check_certificate_upload_file_limit()
        self._credential_serializer = CredentialExtractor(
            private_key_serializer=self._private_key_serializer,
            certificate_collection_serializer=self._certificate_collection_serializer
        ).extract_credential()
        self._is_initialized = True

        # self._validate_credential()


class UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer(FileImportLocalIssuingCaInitializer):
    """Responsible for initializing an Issuing CA from PKCS#12 file."""

    _p12: bytes

    def __init__(self, unique_name: str, p12: bytes, auto_crl: bool, password: None | bytes = None) -> None:

        self.password = password
        self._unique_name = unique_name
        self._auto_crl = auto_crl
        self._p12 = p12

    def _serialize_raw_data(self) -> None:
        credential_serializer = self._credential_serializer_class(self._p12, self.password)
        self._private_key_serializer = credential_serializer.credential_private_key
        self._certificate_collection_serializer = credential_serializer.all_certificates

class UnprotectedFileImportLocalIssuingCaFromSeparateFilesInitializer(FileImportLocalIssuingCaInitializer):
    """Responsible for initializing an Issuing CA from separate files."""

    _private_key: bytes
    _issuing_ca_certificate: bytes
    _additional_certificates: bytes | None

    def __init__(
            self,
            unique_name: str,
            auto_crl: bool,
            private_key_raw: bytes,
            password: None | bytes,
            issuing_ca_certificate_raw: bytes,
            additional_certificates_raw: bytes | None) -> None:

        self.password = password

        self._unique_name = unique_name
        self._auto_crl = auto_crl
        self._private_key = private_key_raw
        self._issuing_ca_certificate = issuing_ca_certificate_raw
        self._additional_certificates = additional_certificates_raw

    def _serialize_raw_data(self) -> None:
        self._private_key_serializer = PrivateKeySerializer(self._private_key, self.password)

        if self._additional_certificates is None:
            self._certificate_collection_serializer = CertificateCollectionSerializer([])

        if not self._additional_certificates:
            certificate_collection = CertificateCollectionSerializer([])
        else:
            certificate_collection = CertificateCollectionSerializer(self._additional_certificates)
        certificate_collection.append(self._issuing_ca_certificate)
        self._certificate_collection_serializer = certificate_collection
