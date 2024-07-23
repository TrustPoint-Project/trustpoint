from __future__ import annotations


from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
import datetime


class CertificateBuilder:
    _builder: x509.CertificateBuilder = x509.CertificateBuilder()
    _private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    _certificate: None | x509.Certificate

    @property
    def builder(self) -> x509.CertificateBuilder:
        return self._builder

    @property
    def certificate(self) -> None | x509.Certificate:
        return self._certificate

    @property
    def private_key(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        return self._private_key

    def create_default_base(self) -> CertificateBuilder:
        one_day = datetime.timedelta(1, 0, 0)
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = self._private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-unittest'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-unittest'),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        self._builder = builder.public_key(public_key)
        return self

    def create_cert(self) -> CertificateBuilder:
        self._certificate = self._builder.sign(
            private_key=self._private_key, algorithm=hashes.SHA256(),
        )
        return self
