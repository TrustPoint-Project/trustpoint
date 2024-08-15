from __future__ import annotations

import abc
from django.db import transaction
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import pkcs12
from django.forms import ValidationError

from pki.models import (
    CertificateModel,
    IssuingCaModel,
    CertificateChainOrderModel,
    TrustStoreModel,
    TrustStoreOrderModel)

from pki.serialization.serializer import PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer

from typing import TYPE_CHECKING

from util.x509.credentials import UnsupportedKeyTypeError

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


# TODO: Exception Handling for whole module!!!
# TODO: Certificate Validation / Issuing CA validation for whole module!!!


# TODO: Validators
class IssuingCaValidator:

    @staticmethod
    def validate(self, full_cert_chain: list[x509.Certificate], private_key: PrivateKey, **kwargs) -> bool:
        return True


class TrustStoreInitializer:
    _unique_name: str
    _trust_store: list[x509.Certificate]

    def __init__(
            self,
            unique_name: str,
            trust_store: bytes | list[x509.Certificate],
            cert_model_class: type(CertificateModel) = CertificateModel,
            trust_store_model_class: type(TrustStoreModel) = TrustStoreModel,
            trust_store_order_model_class: type(TrustStoreOrderModel) = TrustStoreOrderModel) -> None:

        # TODO
        if isinstance(trust_store, bytes):
            trust_store = x509.load_pem_x509_certificates(trust_store)

        self._unique_name = unique_name
        self._trust_store = trust_store

        self._cert_model_class = cert_model_class
        self._trust_store_model_class = trust_store_model_class
        self._trust_store_order_model_class = trust_store_order_model_class

    @transaction.atomic
    def save(self):

        saved_certs = []

        for certificate in self._trust_store:
            saved_certs.append(self._cert_model_class.save_certificate(certificate))

        trust_store_model = self._trust_store_model_class(unique_name=self._unique_name)
        trust_store_model.save()

        for number, certificate in enumerate(saved_certs):
            _trust_store_order_model = self._trust_store_order_model_class()
            _trust_store_order_model.order = number
            _trust_store_order_model.certificate = certificate
            _trust_store_order_model.trust_store = trust_store_model
            _trust_store_order_model.save()


class IssuingCaInitializer(abc.ABC):

    @abc.abstractmethod
    def save(self):
        pass


class LocalIssuingCaFromFileInitializer(IssuingCaInitializer, abc.ABC):
    pass


class LocalUnprotectedIssuingCaFromP12FileInitializer(LocalIssuingCaFromFileInitializer):
    # TODO: check p12 edge cases
    # TODO: -> no issuing ca certificate, no full chain, no key, ...

    _unique_name: str
    _p12: pkcs12
    _issuing_ca_cert: x509.Certificate
    _full_cert_chain: list[x509.Certificate]
    _validator: IssuingCaValidator

    def __init__(
            self,
            unique_name: str,
            p12: bytes | pkcs12,
            password: None | bytes = None,
            validator: IssuingCaValidator = IssuingCaValidator,
            cert_model_class: type(CertificateModel) = CertificateModel,
            issuing_ca_model_class: type(IssuingCaModel) = IssuingCaModel,
            cert_chain_order_model: type(CertificateChainOrderModel) = CertificateChainOrderModel) -> None:

        if isinstance(p12, bytes):
            p12 = pkcs12.load_pkcs12(p12, password)

        self._unique_name = unique_name
        self._p12 = p12
        self._validator = validator

        self._cert_model_class = cert_model_class
        self._issuing_ca_model_class = issuing_ca_model_class
        self._cert_chain_order_model = cert_chain_order_model

        self._extract_key()
        self._extract_issuing_ca_cert()
        self._extract_full_cert_chain()

        self._validate_issuing_ca()

    def _extract_key(self) -> None:
        self._private_key = self._p12.key
        self._private_key_pem = self._p12.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def _extract_issuing_ca_cert(self) -> None:
        self._issuing_ca_cert = self._p12.cert.certificate

    @staticmethod
    def _is_self_signed(certificate: x509.Certificate) -> bool:
        if certificate.subject == certificate.issuer:
            try:
                certificate.verify_directly_issued_by(certificate)
                return True
            except (ValueError, TypeError, InvalidSignature):
                return False

    @staticmethod
    def _get_issuer_certificates(
            certificate: x509.Certificate,
            issuer_candidates: list[x509.Certificate]) -> list[x509.Certificate]:
        issuers = []
        for issuer_candidate in issuer_candidates:
            if certificate.issuer != issuer_candidate.subject:
                continue
            try:
                certificate.verify_directly_issued_by(issuer_candidate)
                issuers.append(issuer_candidate)
            except (ValueError, TypeError, InvalidSignature):
                pass
        return issuers

    @staticmethod
    def _get_fingerprint(certificate: x509.Certificate) -> bytes:
        return certificate.fingerprint(SHA256())

    def _extract_full_cert_chain(self) -> None:
        current_cert = self._issuing_ca_cert
        self._full_cert_chain = [self._issuing_ca_cert]

        if self._is_self_signed(current_cert):
            return

        certs = [cert.certificate for cert in self._p12.additional_certs]
        processed_certs = [current_cert.fingerprint(SHA256())]

        while not self._is_self_signed(current_cert):
            issuers = self._get_issuer_certificates(current_cert, certs)
            if len(issuers) == 0:
                raise ValueError('The PKCS#12 file does not contain the required full certificate chain.')
            if len(issuers) > 1:
                raise ValueError('Found a cross singed certificate in the PKCS#12 file. One single chain is required.')
            issuer = issuers[0]
            fingerprint = self._get_fingerprint(issuer)
            if fingerprint in processed_certs:
                raise ValueError(
                    'The certificate path contains a cycle and does not end on a self-signed Root CA certificate.')
            processed_certs.append(fingerprint)
            self._full_cert_chain.append(issuer)
            current_cert = issuer

        self._full_cert_chain.reverse()

    def _validate_issuing_ca(self) -> None:
        # TODO
        pass

    @transaction.atomic
    def save(self):

        print('saving')
        try:
            saved_certs = [self._cert_model_class.save_certificate(self._issuing_ca_cert)]
        except Exception as exception:
            # TODO: Proper filter
            cert_model = CertificateModel.objects.get(
                cert_pem=self._issuing_ca_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
            )
            raise ValueError(
                f'Provided Issuing CA already configured. Unique Name: {cert_model.issuing_ca_model.unique_name}')

        for certificate in self._full_cert_chain[1:]:
            saved_certs.append(self._cert_model_class.save_certificate(certificate, exist_ok=True))

        issuing_ca_model = self._issuing_ca_model_class(
            unique_name=self._unique_name,
            private_key_pem=self._private_key_pem,
        )

        issuing_ca_model.issuing_ca_certificate = saved_certs[-1]
        issuing_ca_model.root_ca_certificate = saved_certs[0]
        issuing_ca_model.save()

        for number, certificate in enumerate(saved_certs[1:-1]):
            cert_chain_order_model = self._cert_chain_order_model()
            cert_chain_order_model.order = number
            cert_chain_order_model.certificate = certificate
            cert_chain_order_model.issuing_ca = issuing_ca_model
            cert_chain_order_model.save()


class LocalUnprotectedIssuingCaFromSeparateFilesInitializer(LocalIssuingCaFromFileInitializer):

    _unique_name: str
    _private_key: PrivateKeySerializer
    _issuing_ca_cert: None | CertificateSerializer
    _cert_chain: None | CertificateCollectionSerializer
    _full_cert_chain: CertificateCollectionSerializer
    _validator: IssuingCaValidator

    def __init__(
            self,
            unique_name: str,
            private_key_file_raw: bytes,
            password: None | bytes,
            issuing_ca_cert_raw: bytes,
            certificate_chain_raw: None | bytes,
            validator: IssuingCaValidator = IssuingCaValidator,
            cert_model_class: type(CertificateModel) = CertificateModel,
            issuing_ca_model_class: type(IssuingCaModel) = IssuingCaModel,
            cert_chain_order_model: type(CertificateChainOrderModel) = CertificateChainOrderModel
    ) -> None:

        self._cert_model_class = cert_model_class
        self._issuing_ca_model_class = issuing_ca_model_class
        self._cert_chain_order_model = cert_chain_order_model

        self._unique_name = unique_name
        self._private_key = PrivateKeySerializer.from_bytes(private_key_file_raw, password=password)

        self._issuing_ca_cert = CertificateSerializer.from_bytes(issuing_ca_cert_raw)

        if certificate_chain_raw is None:
            self._cert_chain = None
        else:
            self._cert_chain = CertificateCollectionSerializer.from_bytes(certificate_chain_raw)


    #     if not self._issuing_ca_cert:
    #         self._issuing_ca_cert = self._extract_issuing_ca_cert
    #
    #     # self._validate_issuing_ca()
    #
    # def _extract_issuing_ca_cert(self) -> CertificateSerializer:
    #     public_key_from_private_key =
    #     for cert in self._cert_chain.as_crypto():
    #         if
    #
    #
    #
    #
    # def _validate_issuing_ca(self) -> None:
    #     # TODO
    #     pass

    # @transaction.atomic
    # def save(self):
    #
    #     saved_certs = []
    #
    #     for certificate in self._full_cert_chain:
    #         saved_certs.append(self._cert_model_class.save_certificate(certificate))
    #
    #     issuing_ca_model = self._issuing_ca_model_class(
    #         unique_name=self._unique_name,
    #         private_key_pem=self._private_key_pem,
    #     )
    #
    #     issuing_ca_model.issuing_ca_certificate = saved_certs[-1]
    #     issuing_ca_model.root_ca_certificate = saved_certs[0]
    #     issuing_ca_model.save()
    #
    #     for number, certificate in enumerate(saved_certs[1:-1]):
    #         cert_chain_order_model = self._cert_chain_order_model()
    #         cert_chain_order_model.order = number
    #         cert_chain_order_model.certificate = certificate
    #         cert_chain_order_model.issuing_ca = issuing_ca_model
    #         cert_chain_order_model.save()

