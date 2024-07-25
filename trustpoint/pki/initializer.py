from __future__ import annotations
from typing import TYPE_CHECKING


from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
from pathlib import Path


from django.db import transaction


from .models import CertificateModel, IssuingCaModel, CertificateChainOrderModel


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


# TODO: Validators
class IssuingCaValidator:

    @staticmethod
    def validate(self, full_cert_chain: list[x509.Certificate], private_key: PrivateKey, **kwargs) -> bool:
        return True


class IssuingCaInitializer(ABC):

    @abstractmethod
    def save(self):
        pass


class LocalIssuingCaFromFileInitializer(IssuingCaInitializer, ABC):
    pass


class LocalUnprotectedIssuingCaFromP12FileInitializer(LocalIssuingCaFromFileInitializer):

    _unique_name: str
    _p12: pkcs12
    _private_key: PrivateKey
    _private_key_pem: str
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
        print(self._issuing_ca_cert)
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
        pass

    @transaction.atomic
    def save(self):

        print('saving')
        saved_certs = []

        print('saving certs')
        for certificate in self._full_cert_chain:
            saved_certs.append(self._cert_model_class.save_certificate(certificate))
        print('saved_certs')
        print('saving issuing ca model')
        issuing_ca_model = self._issuing_ca_model_class(
            unique_name=self._unique_name,
            private_key_pem=self._private_key_pem,
            )

        print('saved issuing ca model')

        issuing_ca_model.issuing_ca_certificate = saved_certs[-1]
        issuing_ca_model.root_ca_certificate = saved_certs[0]
        issuing_ca_model.save()

        for number, certificate in enumerate(saved_certs[1:-1]):
            cert_chain_order_model = self._cert_chain_order_model()
            cert_chain_order_model.order = number
            cert_chain_order_model.certificate = certificate
            cert_chain_order_model.issuing_ca = issuing_ca_model
            cert_chain_order_model.save()


def abc():
    base_path = Path(__file__).parent.parent.parent.resolve()
    path = base_path / Path('trustpoint/pki')

    with open(path / 'p12.p12', 'rb') as f:
        p12_bytes = f.read()

    le = LocalUnprotectedIssuingCaFromP12FileInitializer('hello', p12_bytes, b'testing321')
    le.save()
