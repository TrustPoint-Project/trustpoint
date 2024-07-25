from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC


from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519


if TYPE_CHECKING:
    from typing import Union
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


class Serializer(ABC):
    pass


class CertificateSerializer(Serializer):
    _certificate: x509.Certificate

    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate

    @classmethod
    def from_bytes(cls, certificate: bytes) -> CertificateSerializer:
        if isinstance(certificate, bytes):
            try:
                certificate = cls._load_pem_certificate(certificate)
            except ValueError:
                try:
                    certificate = cls._load_der_certificate(certificate)
                except ValueError:
                    raise RuntimeError('Failed to load certificate.')
        return CertificateSerializer(certificate)

    @classmethod
    def from_string(cls, certificate: str) -> CertificateSerializer:
        return cls.from_bytes(certificate.encode())

    def get_as_pem(self) -> bytes:
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

    def get_as_der(self) -> bytes:
        return self._certificate.public_bytes(encoding=serialization.Encoding.DER)

    def get_as_crypto(self) -> x509.Certificate:
        return self._certificate

    @staticmethod
    def _load_pem_certificate(certificate: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(certificate)
        except Exception:
            raise ValueError

    @staticmethod
    def _load_der_certificate(certificate: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(certificate)
        except Exception:
            raise ValueError


class PublicKeySerializer:
    _public_key: PublicKey

    def __init__(self, public_key: PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_bytes(cls, public_key: bytes) -> PublicKeySerializer:
        if isinstance(public_key, bytes):
            try:
                public_key = cls._load_pem_public_key(public_key)
            except ValueError:
                try:
                    public_key = cls._load_der_public_key(public_key)
                except ValueError:
                    raise RuntimeError('Failed to load public key.')
        return PublicKeySerializer(public_key)

    @classmethod
    def from_string(cls, public_key: str) -> PublicKeySerializer:
        return cls.from_bytes(public_key.encode())

    @staticmethod
    def _load_pem_public_key(public_key: bytes) -> PublicKey:
        try:
            return serialization.load_pem_public_key(public_key)
        except Exception:
            raise ValueError

    @staticmethod
    def _load_der_public_key(public_key: bytes) -> PublicKey:
        try:
            return serialization.load_der_public_key(public_key)
        except Exception:
            raise ValueError

    def get_as_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def get_as_der(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def get_as_crypto(self) -> PublicKey:
        return self._public_key


class CertificateChainSerializer:
    _certificate_chain: list[x509.Certificate]

    def __init__(self, certificate_chain: list[x509.Certificate]) -> None:
        self._certificate_chain = certificate_chain

    @classmethod
    def from_bytes(cls, certificate_chain: bytes) -> CertificateChainSerializer:
        try:
            certificate_chain = x509.load_pem_x509_certificates(certificate_chain)
        except ValueError:
            raise ValueError('Failed to load certificate chain.')
        return cls(certificate_chain)

    @classmethod
    def from_list_of_bytes(cls, certificate_chain: list[bytes]) -> CertificateChainSerializer:
        cert_chain = []
        for certificate in certificate_chain:
            try:
                cert_chain.append(cls._load_pem_certificate(certificate))
            except ValueError:
                try:
                    cert_chain.append(cls._load_der_certificate(certificate))
                except ValueError:
                    raise ValueError('Failed to load certificate.')
        return cls(cert_chain)

    @classmethod
    def from_string(cls, certificate_chain: str) -> CertificateChainSerializer:
        return cls.from_bytes(certificate_chain.encode())

    @classmethod
    def from_list_of_strings(cls, certificate_chain: list[str]) -> CertificateChainSerializer:
        return cls.from_list_of_bytes([entry.encode() for entry in certificate_chain])

    @staticmethod
    def _load_pem_certificate(certificate: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(certificate)
        except Exception:
            raise ValueError

    @staticmethod
    def _load_der_certificate(certificate: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(certificate)
        except Exception:
            raise ValueError

    def get_as_pem(self) -> bytes:
        return b''.join([cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in self._certificate_chain])

    def get_as_pkcs7_der(self) -> bytes:
        return pkcs7.serialize_certificates(self._certificate_chain, encoding=serialization.Encoding.DER)

    def get_as_pkcs7_pem(self) -> bytes:
        return pkcs7.serialize_certificates(self._certificate_chain, encoding=serialization.Encoding.PEM)

    def get_as_crypto(self) -> list[x509.Certificate]:
        return self._certificate_chain
