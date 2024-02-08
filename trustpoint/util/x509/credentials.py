from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption
from cryptography.x509 import Certificate, ObjectIdentifier
from datetime import datetime


# TODO: use enums for key types and curves
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


# TODO: use key identifier extensions if available to build x509 path
# TODO: check keys - cert matching
# TODO: check signatures
# TODO: check x509 extensions
class P12:

    _attr_name_overrides: dict[ObjectIdentifier, str] = {
        ObjectIdentifier('2.5.4.5'): 'serialNumber'
    }

    def __init__(self, p12: pkcs12.PKCS12KeyAndCertificates) -> None:
        self._p12 = p12

    # TODO: this expects the chain to contain the Issuing CA cert
    # TODO: properly refactor this
    def full_cert_chain_as_json(self) -> list[dict[str, [str, str | None]]]:
        certs = list()
        for crypto_cert in self._p12.additional_certs:
            cert = crypto_cert.certificate
            cert_json = {
                    'Version': cert.version.name,
                    'Serial Number': '0x' + hex(cert.serial_number).upper()[2:],
                    'Subject': cert.subject.rfc4514_string(
                        attr_name_overrides=self._attr_name_overrides
                    ),
                    'Issuer': cert.issuer.rfc4514_string(
                        attr_name_overrides=self._attr_name_overrides
                    ),
                    'Not Valid Before': cert.not_valid_before_utc,
                    'Not Valid After': cert.not_valid_after_utc,
                    'Public Key Type': None,
                    'Public Key Size': str(cert.public_key().key_size) + ' bits',
                    # TODO: names are not standardized, use own OID Enums in the future
                    # noinspection PyProtectedMember
                    'Signature Algorithm': str(cert.signature_algorithm_oid._name)
                }

            if isinstance(self._p12.key, RSAPrivateKey):
                cert_json['Public Key Type'] = 'RSA'
            elif isinstance(self._p12.key, EllipticCurvePrivateKey):
                cert_json['Public Key Type'] = 'ECC'
            else:
                cert_json['Public Key Type'] = 'Unknown'
            certs.append(cert_json)

        certs[0]['heading'] = 'Issuing CA Certificate'
        if len(certs) > 1:
            certs[-1]['heading'] = 'Root CA Certificate'
        if len(certs) > 2:
            for i in range(1, len(certs) - 1):
                certs[i]['heading'] = 'Intermediate CA Certificate'

        return certs

    @classmethod
    def from_bytes(cls, data: bytes, password: bytes | None = None) -> 'P12':
        return cls(pkcs12.load_pkcs12(data, password))

    @property
    def key_type(self) -> str:
        if isinstance(self._p12.key, RSAPrivateKey):
            return 'RSA'
        elif isinstance(self._p12.key, EllipticCurvePrivateKey):
            return 'ECC'

        raise ValueError('Unknown key type. Only RSA and ECC keys are supported.')

    @property
    def key_size(self) -> int:
        return self._p12.key.key_size

    @property
    def curve(self) -> str | None:
        if not isinstance(self._p12.key, EllipticCurvePrivateKey):
            return None

        return self._p12.key.curve.name.upper()

    @property
    def subject(self) -> str | None:

        return self._p12.cert.certificate.subject.rfc4514_string(
            attr_name_overrides=self._attr_name_overrides)

    @property
    def issuer(self) -> str | None:
        return self._p12.cert.certificate.issuer.rfc4514_string(
            attr_name_overrides=self._attr_name_overrides)

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
        return self._p12.additional_certs[-1].certificate.issuer.rfc4514_string(
            attr_name_overrides=self._attr_name_overrides)

    @property
    def common_name(self) -> str:
        common_names = self._p12.cert.certificate.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
        if not common_names:
            return ''

        common_name = ''
        for cn in common_names:
            common_name += f'{cn.value}<br>'
        return common_name[:-4]

    @property
    def root_common_name(self) -> str:
        root_cert_subject = self._p12.additional_certs[-1].certificate.subject
        common_names = root_cert_subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
        if not common_names:
            return ''

        common_name = ''
        for cn in common_names:
            common_name += f'{cn.value}<br>'
        return common_name[:-4]

    @property
    def localization(self) -> str:
        return 'L'

    @property
    def config_type(self) -> str:
        return 'F_P12'


class CredentialUploadHandler:

    @staticmethod
    def parse_and_normalize_p12(data: bytes, password: bytes = b'') -> P12:
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
