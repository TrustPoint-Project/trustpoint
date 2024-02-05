from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
from cryptography.x509 import Certificate
from datetime import datetime


class X509PathBuilder:

    @staticmethod
    def get_x509_cert_chain(certificate: Certificate, certificates: list[Certificate]) -> list[Certificate]:
        result = [certificate]
        root_found = False
        child_subject = certificate.issuer.public_bytes()

        while not root_found:
            for cert in certificates:
                cert_subject = cert.subject.public_bytes()
                cert_issuer = cert.issuer.public_bytes()
                if child_subject == cert_subject:
                    if cert_subject == cert_issuer:
                        result.append(cert)
                        root_found = True
                        break
                    else:
                        child_subject = cert.issuer.public_bytes()
                        result.append(cert)
                        break

            else:
                raise ValueError('Certificate chain is not complete.')

        return result


# TODO: supported key and algorithm types
# TODO: use key identifier extensions if available to build x509 path
class P12:

    def __init__(self, p12: pkcs12.PKCS12KeyAndCertificates) -> None:
        self._p12 = p12

    @classmethod
    def from_bytes(cls, data: bytes, password: bytes | None = None) -> 'P12':
        return cls(pkcs12.load_pkcs12(data, password))

    @property
    def key_type(self) -> str:
        if isinstance(self._p12.key, RSAPrivateKey):
            return 'rsa'
        elif isinstance(self._p12.key, EllipticCurvePrivateKey):
            return 'ecc'

        raise ValueError('Unknown key type. Only RSA and ECC keys are supported.')

    @property
    def key_size(self) -> int:
        return self._p12.key.key_size

    @property
    def curve(self) -> str | None:
        if not isinstance(self._p12.key, EllipticCurvePrivateKey):
            return None

        return self._p12.key.curve.name

    @property
    def subject(self) -> str | None:
        return self._p12.cert.certificate.subject.rfc4514_string()

    @property
    def issuer(self) -> str | None:
        return self._p12.cert.certificate.issuer.rfc4514_string()

    @property
    def public_bytes(self) -> bytes:
        return pkcs12.serialize_key_and_certificates(
            self._p12.cert.friendly_name,
            self._p12.key,
            self._p12.cert.certificate,
            self._p12.additional_certs,
            NoEncryption())

    @property
    def not_valid_before(self) -> datetime:
        return self._p12.cert.certificate.not_valid_before_utc

    @property
    def not_valid_after(self) -> datetime:
        return self._p12.cert.certificate.not_valid_after_utc

    @property
    def chain_not_valid_before(self) -> datetime:
        # TODO
        return self._p12.cert.certificate.not_valid_before_utc

    @property
    def chain_not_valid_after(self) -> datetime:
        return self._p12.cert.certificate.not_valid_after_utc

    @property
    def root_subject(self) -> str:
        return self._p12.cert.certificate.issuer.rfc4514_string()


class CredentialUploadHandler:

    @staticmethod
    def parse_and_normalize_p12(data: bytes, password: bytes) -> P12:
        p12 = pkcs12.load_pkcs12(data, password)
        cert = p12.cert.certificate
        key = p12.key
        cert_chain = X509PathBuilder.get_x509_cert_chain(
            p12.cert.certificate, [cert.certificate for cert in p12.additional_certs])
        friendly_name = b''
        return P12.from_bytes(
            pkcs12.serialize_key_and_certificates(friendly_name, key, cert, cert_chain, NoEncryption()))

    @staticmethod
    def parse_and_normalize_pem(cert: bytes, cert_chain: bytes, key: bytes, password: bytes) -> P12:
        pass
