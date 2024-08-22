from __future__ import annotations

import abc
import logging

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

from pki.models import CertificateModel, IssuingCaModel, CertificateChainOrderModel

from pki.serializer import (
    PrivateKeySerializer,
    CertificateCollectionSerializer,
    CredentialSerializer
)

from . import IssuingCaInitializer
from . import IssuingCaInitializerError

from pki.util import Sha256Fingerprint, CredentialExtractor

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]

log = logging.getLogger('tp.pki.initializer')


class FileImportLocalIssuingCaInitializerError(IssuingCaInitializerError):
    pass


class InternalServerError(FileImportLocalIssuingCaInitializerError):
    """Raised if an unexpected error occurred.

     E.g. is raised, if .initialize() is not called before .save()
     """

    def __init__(self, message: None | str = None) -> None:
        if message:
            super().__init__(message=message)
        else:
            super().__init__(message=_(
                f'An unexpected internal server error occurred.'
                f'Please contact the Trust-Point support '))


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


class IssuingCaAlreadyExistsError(FileImportLocalIssuingCaInitializerError):
    """Raised if an Issuing CA already exists for a corresponding Issuing CA certificate."""

    def __init__(self, name: str) -> None:
        super().__init__(message=_(f'Issuing CA already exists with unique name: {name}.'))


class FileImportLocalIssuingCaInitializer(IssuingCaInitializer, abc.ABC):
    """Base class for importing a new Issuing CA through a file upload(s)."""

    _CERTIFICATE_UPLOAD_FILE_LIMIT: int = 100

    _unique_name: str
    _auto_crl: bool
    _password: None | bytes

    _is_initialized: bool = False

    _credential_serializer: CredentialSerializer
    _private_key_serializer: PrivateKeySerializer
    _certificate_collection_serializer: CertificateCollectionSerializer

    _credential_serializer_class: type[CredentialSerializer] = CredentialSerializer

    _cert_model_class: type[CertificateModel] = CertificateModel
    _issuing_ca_model_class: type[IssuingCaModel] = IssuingCaModel
    _cert_chain_order_model_class: type[CertificateChainOrderModel] = CertificateChainOrderModel


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

    @transaction.atomic
    def save(self):
        """Saves the initialized Issuing CA in the database.

        Raises:
            InternalServerError: If the Issuing CA was not yet initialized or some other unexpected error occurred.
        """

        if not self._is_initialized:
            raise InternalServerError

        try:
            issuing_ca_certificate = self._credential_serializer.credential_certificate.as_crypto()

            try:
                saved_certs = [self._cert_model_class.save_certificate(issuing_ca_certificate)]
            except ValueError:

                cert_model = self._cert_model_class.objects.get(
                    sha256_fingerprint=Sha256Fingerprint.get_fingerprint_hex_str(issuing_ca_certificate))

                if hasattr(cert_model, 'issuing_ca_model'):
                    raise IssuingCaAlreadyExistsError(name=cert_model.issuing_ca_model.unique_name)

                saved_certs = [cert_model]

            for certificate in self._credential_serializer.additional_certificates.crypto_iterator():
                saved_certs.append(self._cert_model_class.save_certificate(certificate, exist_ok=True))

            issuing_ca_model = self._issuing_ca_model_class(
                unique_name=self._unique_name,
                auto_crl=self._auto_crl,
                private_key_pem=self._credential_serializer.credential_private_key.as_pkcs1_pem(None)
            )

            issuing_ca_model.issuing_ca_certificate = saved_certs[0]
            issuing_ca_model.root_ca_certificate = saved_certs[-1]
            issuing_ca_model.save()

            for number, certificate in enumerate(saved_certs[1:-1]):
                cert_chain_order_model = self._cert_chain_order_model_class()
                cert_chain_order_model.order = number
                cert_chain_order_model.certificate = certificate
                cert_chain_order_model.issuing_ca = issuing_ca_model
                cert_chain_order_model.save()
        except Exception as exception:
            error_msg = str(exception)
            if len(error_msg) >= 4:
                error_msg = error_msg[2:-2]
            log.error(error_msg)
            raise InternalServerError(error_msg)


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
