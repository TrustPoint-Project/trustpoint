"""Utils for parsing and normalizing PKCS#12 and PEM files."""


from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import NoEncryption, load_pem_private_key, pkcs12
from cryptography.x509 import Certificate, ObjectIdentifier, ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


if TYPE_CHECKING:
    from datetime import datetime


class CredentialsError(Exception):
    """Parent Exception class for exceptions raised within the util.x509 package."""

    def __init__(self, message: str) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        super().__init__(message)


class PemParseError(CredentialsError):
    """Raised if parsing of a PEM file failed."""

    def __init__(self) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Failed to parse PEM file.'
        super().__init__(exc_msg)


class P12ParseError(CredentialsError):
    """Raised if parsing of a P12 file failed."""

    def __init__(self) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Failed to parse PKCS#12 file.'
        super().__init__(exc_msg)


class P12SerializeError(CredentialsError):
    """Raised if the serialization of a P12 file failed."""

    def __init__(self) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Failed to serialize PKCS#12 file.'
        super().__init__(exc_msg)


class X509CertificateChainBuilderError(CredentialsError):
    """Raised if the X509 path and chain cannot be constructed."""

    def __init__(self) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Failed to construct certificate chain.'
        super().__init__(exc_msg)


class UnsupportedKeyTypeError(CredentialsError):
    """Raised if key type is not supported."""

    def __init__(self) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unsupported key type. Only RSA and ECC keys are supported.'
        super().__init__(exc_msg)


# TODO(Alex): use enums for key types and curves
class X509CertificateChainBuilder:
    """Provides methods for building X.509 certificate chains and paths."""

    @staticmethod
    def get_x509_cert_chain(certificate: Certificate, certificates: list[Certificate]) -> list[Certificate]:
        """Returns a certificate chain containing the certificate up to the root certificate.

        Args:
            certificate (x509.Certificate):
                The certificate for which the certificate chain will be constructed.
                The certificate chain will contain this certificate the first element.
            certificates (list[x509.Certificate]):
                List of certificates which is searched for the required certificates to build the certificate chain.

        Returns:
            list[Certificate]:
                The certificate chain containing the root certificate as last element and the provided
                certificate as the first element.

        Raises:
            X509CertificateChainBuilderError
        """
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
                    child_subject = cert.issuer.public_bytes()
                    result.append(cert)
                    break

            else:
                raise X509CertificateChainBuilderError

        return result


# TODO(Alex): use key identifier extensions if available to build x509 path
# TODO(Alex): check keys - cert matching
# TODO(Alex): check signatures
# TODO(Alex): check x509 extensions
class P12:
    """Provides methods for parsing and normalizing PKCS#12 files."""

    _attr_name_overrides: dict[ObjectIdentifier, str]

    def __init__(self, p12: pkcs12.PKCS12KeyAndCertificates) -> None:
        """Constructor of the P12 object.

        Args:
            p12 (pkcs12.PKCS12KeyAndCertificates):
                Python cryptography PKCS#12 object.
        """
        self._attr_name_overrides = {ObjectIdentifier('2.5.4.5'): 'serialNumber'}
        self._p12 = p12

    @classmethod
    def from_bytes(cls: type(P12), data: bytes, password: bytes | None = None) -> P12:
        """Creates a P12 object from a binary representation of a PKCS#12 file.

        Args:
            data (bytes):
                The binary representation of a PKCS#12 file.
            password (bytes | None):
                The password for the PKCS#12 file if it is encrypted.
                If the PKCS#12 is not encrypted either b'' or None can be used to provide no password.

        Raises:
            P12Error:
                If parsing of the PKCS#12 file failed. Either through a malformed PKCS#12 file or a wrong password.
        """
        if password == b'':
            password = None

        try:
            return cls(pkcs12.load_pkcs12(data, password))
        # TODO(Alex): check which Exceptions could occur
        except Exception as exception:  # noqa: BLE001
            raise P12ParseError from exception

    # TODO(Alex): this expects the chain to contain the Issuing CA cert
    # TODO(Alex): properly refactor this
    def full_cert_chain_as_dict(self) -> list[dict]:
        """Converts the PKCS#12 object to a list of certificates in a python native form.

        Returns:
            list[dict]:
                List of certificates in a python native form.

        Raises:
            P12ParseError:
                Raised if the full certificate chain could not be constructed from the PKCS#12 file.
        """
        try:
            certs = []
            for crypto_cert in self._p12.additional_certs:
                cert = crypto_cert.certificate
                # noinspection PyProtectedMember
                cert_dict = {
                    'Version': cert.version.name,
                    'Serial Number': '0x' + hex(cert.serial_number).upper()[2:],
                    'Subject': cert.subject.rfc4514_string(attr_name_overrides=self._attr_name_overrides),
                    'Issuer': cert.issuer.rfc4514_string(attr_name_overrides=self._attr_name_overrides),
                    'Not Valid Before': cert.not_valid_before_utc,
                    'Not Valid After': cert.not_valid_after_utc,
                    'Public Key Type': None,
                    'Public Key Size': str(cert.public_key().key_size) + ' bits',
                    # TODO(Alex): names are not standardized, use own OID Enums in the future
                    'Signature Algorithm': str(cert.signature_algorithm_oid._name),  # noqa: SLF001
                    'Extensions': []
                }

                if isinstance(self._p12.key, RSAPrivateKey):
                    cert_dict['Public Key Type'] = 'RSA'
                elif isinstance(self._p12.key, EllipticCurvePrivateKey):
                    cert_dict['Public Key Type'] = 'ECC'
                else:
                    cert_dict['Public Key Type'] = 'Unknown'
                certs.append(cert_dict)

                try:
                    basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                    bc_values = {
                        '__name': 'Basic Constraints',
                        'OID': basic_constraints.oid.dotted_string,
                        'Critical': basic_constraints.critical,
                        'CA': getattr(basic_constraints.value, 'ca', None),
                        'Path Length': getattr(basic_constraints.value, 'path_length', None)
                    }
                    cert_dict['Extensions'].append(bc_values)
                except ExtensionNotFound:
                    pass

                # KeyUsage
                # ExtendedKeyUsage

                # AuthorityKeyIdentifier
                # SubjectKeyIdentifier

                # SubjectAlternativeName

            certs[0]['heading'] = 'Issuing CA Certificate'
            if len(certs) >= 2:  # noqa: PLR2004
                certs[-1]['heading'] = 'Root CA Certificate'
            if len(certs) >= 3:  # noqa: PLR2004
                for i in range(1, len(certs) - 1):
                    certs[i]['heading'] = 'Intermediate CA Certificate'

        # TODO(Alex): check which Exceptions could occur
        except (KeyError, ValueError, TypeError) as exception:
            raise P12ParseError from exception

        else:
            return certs

    # TODO(Alex): Handle cases in which no private key is available within the PKCS#12 file
    @property
    def key_type(self) -> str:
        """Gets the key type of the private key contained in the PKCS#12 file.

        Returns:
            str:
                RSA if RSAPrivateKey found.
                ECC if EllipticCurvePrivateKey found.

        Raises:
            UnknownKeyTypeError:
                Raised if the private key is neither of type RSA nor ECC.
        """
        if isinstance(self._p12.key, RSAPrivateKey):
            return 'RSA'
        if isinstance(self._p12.key, EllipticCurvePrivateKey):
            return 'ECC'

        raise UnsupportedKeyTypeError

    @property
    def key_size(self) -> int:
        """Gets the key size in number of bits.

        Returns:
            int:
                The key size in number of bits.
        """
        return self._p12.key.key_size

    @property
    def curve(self) -> str:
        """Gets the name of the curve if the private key is of type ECC.

        Returns:
            str:
                Empty string '' if the private key is not of type ECC.
                Name of the curve if the private key is of type ECC.
        """
        if not isinstance(self._p12.key, EllipticCurvePrivateKey):
            return ''

        return self._p12.key.curve.name.upper()

    @property
    def subject(self) -> str | None:
        """Gets the subject of the certificate as RFC4514 string.

        Returns:
            str | None:
                Subject of the certificate as RFC 4514 string if available.
                Otherwise, it returns None.
        """
        return self._p12.cert.certificate.subject.rfc4514_string(attr_name_overrides=self._attr_name_overrides)

    @property
    def issuer(self) -> str | None:
        """Gets the issuer of the certificate as RFC4514 string.

        Returns:
            str | None:
                Issuer of the certificate as RFC 4514 string if available.
                Otherwise, it returns None.
        """
        return self._p12.cert.certificate.issuer.rfc4514_string(attr_name_overrides=self._attr_name_overrides)

    @property
    def public_bytes(self) -> bytes:
        """Gets the public bytes of the PKCS#12 file.

        These bytes can be written to file to get a valid PKCS#12 file.

        Note:
            The returned PKCS#12 file is currently not encrypted.

        Raises:
            P12SerializeError:
                Raised if the PKCS#12 serialization failed.
        """
        try:
            return pkcs12.serialize_key_and_certificates(
                self._p12.cert.friendly_name,
                self._p12.key,
                self._p12.cert.certificate,
                self._p12.additional_certs,
                NoEncryption(),
            )
        # TODO(Alex): check which Exceptions could occur
        except Exception as exception:  # noqa: BLE001
            raise P12SerializeError from exception

    @property
    def not_valid_before(self) -> datetime:
        """Gets the datetime of the not_valid_before field of the certificate.

        Returns:
            datetime.datetime:
                Datetime (UTC) of the not_valid_before field of the certificate.
        """
        return self._p12.cert.certificate.not_valid_before_utc

    @property
    def not_valid_after(self) -> datetime:
        """Gets the datetime of the not_valid_after field of the certificate.

        Returns:
            datetime.datetime:
                Datetime (UTC) of the not_valid_after field of the certificate.
        """
        return self._p12.cert.certificate.not_valid_after_utc

    @property
    def root_subject(self) -> str:
        """Gets the subject of the root certificate as RFC4514 string.

        Returns:
            str | None:
                Subject of the root certificate as RFC 4514 string if available.
                Otherwise, it returns None.
        """
        return self._p12.additional_certs[-1].certificate.issuer.rfc4514_string(
            attr_name_overrides=self._attr_name_overrides
        )

    @property
    def common_name(self) -> str:
        """Gets the common name of the certificate.

        Returns:
            str:
                Common name of the certificate.
                If the subject contains multiple common name entries, they are concatenated with <br> as a delimiter.
                If the subject does not contain a common name entry, an empty string is returned.
        """
        common_names = self._p12.cert.certificate.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
        if not common_names:
            return ''

        common_name = ''
        for cn in common_names:
            common_name += f'{cn.value}<br>'
        return common_name[:-4]

    @property
    def root_common_name(self) -> str:
        """Gets the common name of the root certificate.

        Returns:
            str:
                Common name of the root certificate.
                If the subject contains multiple common name entries, they are concatenated with <br> as a delimiter.
                If the subject does not contain a common name entry, an empty string is returned.
        """
        root_cert_subject = self._p12.additional_certs[-1].certificate.subject
        common_names = root_cert_subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
        if not common_names:
            return ''

        common_name = ''
        for cn in common_names:
            common_name += f'{cn.value}<br>'
        return common_name[:-4]

    # TODO(Alex): Refactor for remote issuing CAs
    @property
    def localization(self) -> str:
        """Gets the localization of the issuing CA.

        This is temporary and needs to be refactored as soon as remote issuing CAs are supported.
        It is also possible to remove this from the current class and integrate it into another structure.

        Returns:
            str:
                L for local.
        """
        return 'L'

    # TODO(Alex): Refactor this
    @property
    def config_type(self) -> str:
        """Gets the config_type of the issuing CA.

        This is temporary and needs to be refactored.
        It is also possible to remove this from the current class and integrate it into another structure.

        Returns:
            str:
                L for local.
        """
        return 'F_P12'


class CredentialUploadHandler:
    """Provides utility functions for parsing and normalizing PKCS#12 and PEM files."""

    @staticmethod
    def parse_and_normalize_p12(data: bytes, password: bytes = b'') -> P12:
        """Parses and normalizes a PKCS#12 file.

        The normalized PKCS#12 file is not encrypted and contains a main certificate,
        a certificate chain which contains the main certificate and certificates
        up to and including the root certificate and a private key.
        All friendly names are empty bytes: b''.

        Args:
            data (bytes): The PKCS#12 file as bytes.
            password (bytes): The password required to decrypt the PKCS#12 file.

        Returns:
            P12:
                Object that wraps a python cryptography normalized PKCS#12 object.

        Raises:
            P12ParseError:
                Raised if parsing and normalizing of the PKCS#12 file failed.
        """
        try:
            p12 = pkcs12.load_pkcs12(data, password)
            cert = p12.cert.certificate
            key = p12.key
            cert_chain = X509CertificateChainBuilder.get_x509_cert_chain(
                p12.cert.certificate, [cert.certificate for cert in p12.additional_certs]
            )
            friendly_name = b''
            return P12.from_bytes(
                pkcs12.serialize_key_and_certificates(friendly_name, key, cert, cert_chain, NoEncryption())
            )
        except Exception as exception:  # noqa: BLE001
            raise P12ParseError from exception

    @staticmethod
    def parse_pem_cert(cert: bytes) -> Certificate:
        """Parses a certificate in PEM format.

        Args:
            cert:
                The certificate in PEM format as bytes.

        Returns:
            x509.Certificate:
                Python cryptography x509.Certificate object.

        Raises:
            PemParseError:
                Raised if parsing and normalizing of the PEM file failed.
        """
        try:
            return x509.load_pem_x509_certificate(cert)
        except Exception as exception:  # noqa: BLE001
            raise PemParseError from exception

    @staticmethod
    def parse_pem_cert_chain(cert: Certificate, cert_chain: bytes) -> list[Certificate]:
        """Parses a certificate in PEM format.

        Args:
            cert (x509.Certificate):
                The certificate in PEM format as bytes.
            cert_chain (bytes):
                Certificate chain or trust store in PEM format.

        Returns:
            list[x509.Certificate]:
                Python cryptography x509.Certificate object.

        Raises:
            PemParseError:
                Raised if parsing and normalizing of the PEM file failed.
        """
        try:
            crypto_cert_chain = x509.load_pem_x509_certificates(cert_chain)
            return X509CertificateChainBuilder.get_x509_cert_chain(cert, crypto_cert_chain)
        except Exception as exception:  # noqa: BLE001
            raise PemParseError from exception

    @staticmethod
    def parse_pem_key(key: bytes, password: bytes | None = None) -> RSAPrivateKey | EllipticCurvePrivateKey:
        """Parses a key in PEM format.

        Args:
            key (bytes):
                The key in PEM format as bytes.
            password (bytes):
                The password for decrypting the key.

        Returns:
            RSAPrivateKey | EllipticCurvePrivateKey:
                The key as python cryptography key object.

        Raises:
            PemParseError:
                Raised if parsing and normalizing of the PEM file failed.
        """
        if password is not None and not password:
            password = None
        try:
            return load_pem_private_key(key, password)
        except Exception as exception:  # noqa: BLE001
            raise PemParseError from exception

    @staticmethod
    def parse_and_normalize_x509_crypto(
        cert: Certificate, cert_chain: list[Certificate], key: RSAPrivateKey | EllipticCurvePrivateKey
    ) -> P12:
        """Parses PEM files and serializes them into a normalized PKCS#12 file.

        Args:
            cert (x509.Certificate):
                A python cryptography certificate object.
            cert_chain (list[x509.Certificate]):
                A list of python cryptography certificate objects.
            key (RSAPrivateKey | EllipticCurvePrivateKey):
                A python cryptography key object.

        Returns:
            P12:
            Object that wraps a python cryptography normalized PKCS#12 object.

        Raises:
            P12ParseError:
                Raised if parsing and normalizing of the PKCS#12 file failed.
        """
        try:
            friendly_name = b''
            return P12.from_bytes(
                pkcs12.serialize_key_and_certificates(friendly_name, key, cert, cert_chain, NoEncryption())
            )
        except Exception as exception:  # noqa: BLE001
            raise PemParseError from exception
