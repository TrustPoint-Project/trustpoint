from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12


from . import Serializer, PublicKeySerializer



class CertificateSerializer(Serializer):
    """The CertificateSerializer class provides methods for serializing and loading a certificate.

    Warnings:
        The CertificateSerializer class does not evaluate or validate any contents of the certificate.

    **CertificateSerializer UML Class Diagram**

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer

        class CertificateSerializer {
            -_certificate: x509.Certificate
            --
            +<<create>> CertificateSerializer(certificate)
            {static} +<<create>> from_crypto(certificate)
            {static} +<<create>> from_bytes(certificate_data)
            {static} +<<create>> from_string(certificate_data)

            +public_key_serializer() : PublicKeySerializer

            +as_der() : bytes
            +as_crypto() : x509.Certificate

            {static} -_load_pem_certificate(certificate_data) : x509.Certificate
            {static} -_load_der_certificate(certificate_data) : x509.Certificate
        }

        Serializer <|-- CertificateSerializer
    """

    _certificate: x509.Certificate
    _public_key_serializer: None | PublicKeySerializer = None

    def __init__(self, certificate: x509.Certificate) -> None:
        """Inits the CertificateSerializer class.

        Args:
            certificate: The certificate to serialize.

        Raises:
            TypeError: If the certificate is not a x509.Certificate instance.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError('Certificate must be an instance of x509.Certificate.')

        self._certificate = certificate

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Property to get the corresponding PublicKeySerializer object (lazy loading).

        Returns:
            PublicKeySerializer: The corresponding PublicKeySerializer object.
        """
        if self._public_key_serializer is None:
            self._public_key_serializer = PublicKeySerializer(self._certificate.public_key())
        return self._public_key_serializer

    @classmethod
    def from_crypto(cls, certificate: x509.Certificate) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a x509.Certificate instance.

        Args:
            certificate: The certificate to serialize.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            TypeError: If the certificate is not a x509.Certificate instance.
        """
        return cls(certificate)

    @classmethod
    def from_bytes(cls, certificate_data: bytes) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a bytes object.

        Args:
            certificate_data: Bytes that contains a certificate in either DER or PEM format.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            ValueError: If loading of the certificate from bytes failed.
        """
        try:
            return cls(cls._load_pem_certificate(certificate_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_der_certificate(certificate_data))
        except ValueError:
            pass

        raise ValueError('Failed to load certificate. May be malformed or not in a DER or PEM format.')

    @classmethod
    def from_string(cls, certificate_data: str) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a string object.

        Args:
            certificate_data: String that contains a certificate in PEM format.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            ValueError: If loading of the certificate from string failed.
        """
        return cls.from_bytes(certificate_data.encode())

    def as_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PEM format.

        Returns:
            bytes: Bytes that contains the certificate in PEM format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

    def as_der(self) -> bytes:
        """Gets the associated certificate as bytes in DER format.

        Returns:
            bytes: Bytes that contains the certificate in DER format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.DER)

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 PEM format.

        Returns:
            bytes: Bytes that contains the certificate in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates([self._certificate], serialization.Encoding.PEM)

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contains the certificate in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates([self._certificate], serialization.Encoding.DER)

    def as_crypto(self) -> x509.Certificate:
        """Gets the associated certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The associated certificate as x509.Certificate instance.
        """
        return self._certificate

    @staticmethod
    def _load_pem_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(certificate_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @staticmethod
    def _load_der_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(certificate_data)
        except Exception:   # noqa: BLE001
            raise ValueError


class CertificateCollectionSerializer(Serializer):
    """The CertificateCollectionSerializer class provides methods for serializing and loading certificate collections.

    Certificate collections are lists of single certificates. The order will be preserved. Usually these collections
    will either be a certificate chain or a trust store.

    Warnings:
        The CertificateCollectionSerializer class does not evaluate or validate any contents of the certificate
        collection, i.e. no certificate chains are validated.

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer
        class CertificateSerializer
        class CertificateCollectionSerializer {
            -_certificate_collection: list[x509.Certificate]
            -_certificate_serializer_class: type[CertificateSerializer]
            --
            +<<create>> CertificateCollectionSerializer(certificate_collection)
            {static} +<<create>> from_crypto(credential_private_key, credential_certificate, additional_certificates)
            {static} +<<create>> from_crypto_pkcs12(p12)
            {static} +<<create>> from_bytes(credential_data, password)
            {static} +<<create>> from_string(certificate_collection_data)
            {static} +<<create>> from_list_of_bytes(certificate_collection_data)
            {static} +<<create>> from_list_of_strings(certificate_collection_data)

            +as_pkcs12(friendly_name, password) : bytes
            +as_crypto() : bytes

            +get_credential_private_key_serializer() : PrivateKeySerializer
            +get_credential_certificate_serializer() : CertificateSerializer
            +get_additional_certificate_serializer() : CertificateCollectionSerializer
            +get_certificate_collection_serializer() : CertificateCollectionSerializer

            {static} -_load_pkcs12(p12_data, password) : pkcs12.PKCS12KeyAndCertificates
        }

        Serializer <|-- CertificateCollectionSerializer
        Serializer <|-- CertificateSerializer
        CertificateCollectionSerializer --o CertificateSerializer
    """

    _certificate_collection: list[x509.Certificate]
    _certificate_serializer_class: type[CertificateSerializer] = CertificateSerializer

    def __init__(self, certificate_collection: list[x509.Certificate]) -> None:
        """Inits the CertificateCollectionSerializer class.

        Args:
            certificate_collection: A list of x509.Certificates representing the collection.

        Raises:
            ValueError: If the list is empty.
            TypeError: If certificate_collection is not a list of x509.Certificates.
        """
        if not isinstance(certificate_collection, list):
            raise TypeError('certificate_collection must be a list of x509.Certificates.')

        if not certificate_collection:
            raise ValueError('certificate_collection must contain at least one x509.Certificate instance.')

        for certificate in certificate_collection:
            if not isinstance(certificate, x509.Certificate):
                raise TypeError('certificate_collection contains at least one element that is not a x509.Certificate.')

        self._certificate_collection = certificate_collection

    @classmethod
    def from_crypto(cls, certificate_collection: list[x509.Certificate]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of x509.Certificate instances.

        Args:
            certificate_collection: A list of x509.Certificates to serialize.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If the list is empty.
            TypeError: If certificate_collection is not a list of x509.Certificates.
        """
        return cls(certificate_collection)

    @classmethod
    def from_crypto_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a pkcs12.PKCS12 instance.

        Args:
            p12: A pkcs12.PKCS12 instance containing the certificate that shall be serialized.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If the pkcs12.PKCS12 instance does not contain any certificates.
        """
        certificates = [p12.cert.certificate]
        certificates.extend([certificate.certificate for certificate in p12.additional_certs])
        return cls(certificates)

    @classmethod
    def from_bytes(
        cls, certificate_collection_data: bytes, password: None | bytes = None
    ) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a bytes object.

        Args:
            certificate_collection_data: Bytes that contain a collection of certificates in
                PEM, PKCS#7 PEM, PKCS#7 DER or PKCS#12 format.
            password: Password as bytes if the content is encrypted, None otherwise.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        try:
            return cls(cls._load_pem(certificate_collection_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_pkcs7_pem(certificate_collection_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_pkcs7_der(certificate_collection_data))
        except ValueError:
            pass

        try:
            p12 = cls._load_pkcs12(certificate_collection_data, password)
            return cls.from_crypto_pkcs12(p12)
        except ValueError:
            pass

        raise ValueError(
            'Failed to load certificate collection. '
            'May be an incorrect password, malformed data or an unsupported format.'
        )

    @classmethod
    def from_string(cls, certificate_collection_data: str) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a string object.

        Args:
            certificate_collection_data: String that contain a collection of certificates in
                PEM or PKCS#7 PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        return cls.from_bytes(certificate_collection_data.encode())

    @classmethod
    def from_list_of_bytes(cls, certificate_collection_data: list[bytes]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of bytes objects.

        Args:
            certificate_collection_data: A list of bytes that contain certificates in DER or PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        try:
            return cls(
                [
                    CertificateSerializer.from_bytes(certificate).as_crypto()
                    for certificate in certificate_collection_data
                ]
            )
        except Exception:   # noqa: BLE001
            raise ValueError(
                'Failed to load certificate collection. '
                'May be an incorrect password, malformed data or an unsupported format.'
            )

    @classmethod
    def from_list_of_strings(cls, certificate_collection_data: list[str]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of string objects.

        Args:
            certificate_collection_data: A list of strings that contain certificates in PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        return cls.from_list_of_bytes([cert.encode() for cert in certificate_collection_data])

    def as_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PEM format.
        """
        return b''.join([CertificateSerializer(certificate).as_pem() for certificate in self._certificate_collection])

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates(self._certificate_collection, serialization.Encoding.PEM)

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates(self._certificate_collection, serialization.Encoding.DER)

    def as_crypto(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: List of x509.Certificate instances.
        """
        return self._certificate_collection

    @classmethod
    def _load_pem(cls, pem_data: bytes) -> list[x509.Certificate]:
        try:
            return x509.load_pem_x509_certificates(pem_data)
        except Exception as exception:  # noqa: BLE001
            raise ValueError from exception

    @classmethod
    def _load_pkcs7_pem(cls, p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_pem_pkcs7_certificates(p7_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @classmethod
    def _load_pkcs7_der(cls, p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_der_pkcs7_certificates(p7_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @classmethod
    def _load_pkcs12(cls, p12_data: bytes, password: None | bytes = None) -> pkcs12.PKCS12KeyAndCertificates:
        try:
            return pkcs12.load_pkcs12(p12_data, password)
        except Exception:   # noqa: BLE001
            raise ValueError
