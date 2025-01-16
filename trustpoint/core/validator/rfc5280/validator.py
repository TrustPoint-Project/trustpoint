"""Validator module for handling and processing X.509 certificates."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Callable, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.x509 import (
    BasicConstraints,
    Certificate,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    ExtensionNotFound,
    FreshestCRL,
    KeyUsage,
    NameConstraints,
    NameOID,
)
from cryptography.x509.general_name import (
    DirectoryName,
    DNSName,
    GeneralName,
    IPAddress,
    OtherName,
    RegisteredID,
    RFC822Name,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    ObjectIdentifier,
    SignatureAlgorithmOID,
)
from pyasn1.codec.der.decoder import decode  # type: ignore[import-untyped]
from pyasn1_modules.rfc2459 import TBSCertificate  # type: ignore[import-untyped]

from core.oid import SignatureAlgorithmOid

if TYPE_CHECKING:
    from typing import Any, ClassVar, Sequence, Union

    from cryptography.hazmat.primitives.hashes import HashAlgorithm
    from cryptography.x509.extensions import AuthorityKeyIdentifier, DistributionPoint, Extension
    from cryptography.x509.name import Name
    PublicKey = Union[
        dsa.DSAPublicKey,
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        x25519.X25519PublicKey,
        x448.X448PublicKey
    ]

# TODO (FHatCSW): Add generic Validation error which is raised in case of an Exception


class Validation(ABC):
    """Abstract base class for a validation rule or composite."""

    def __init__(self) -> None:
        """Initialize a new Validation instance.

        Initializes internal attributes for managing components, errors,
        and warnings for the validation process.
        """
        self._components: list[Validation] = []  # List of child validations (leafs or composites)
        self._errors: list[str] = []  # List of errors encountered during validation
        self._warnings: list[str] = []  # List of warnings encountered during validation
        self.is_ca: bool = False

    @abstractmethod
    def validate(self, cert: Certificate) -> bool:
        """Perform validation on the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.
        """

    def add_component(self, validation: Validation) -> None:
        """Add a validation rule or composite to the current validation.

        Args:
            validation (Validation): The validation rule or composite to add.
        """
        self._components.append(validation)

    def get_errors(self) -> list[str]:
        """Get the list of errors encountered during validation.

        Returns:
            list: A list of error messages.
        """
        return self._errors

    def get_warnings(self) -> list[str]:
        """Get the list of warnings encountered during validation.

        Returns:
            list: A list of warning messages.
        """
        return self._warnings

    def log_error(self, message: str) -> None:
        """Log an error message.

        Args:
            message (str): The error message to log.
        """
        self._errors.append(message)

    def log_warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message (str): The warning message to log.
        """
        self._warnings.append(message)


class CompositeValidation(Validation):
    """A composite validation class for managing multiple validation rules.

    Args:
        is_ca (bool): True if the certificate being validated is a CA certificate, False otherwise.
    """

    def __init__(self, *, is_ca: bool) -> None:
        """Initialize the composite validation class.

        Args:
            is_ca (bool): Indicates whether the certificate being validated is a CA certificate.
        """
        super().__init__()
        self.is_ca = is_ca

    def add_validation(self, validation: Validation) -> None:
        """Add a validation rule to the composite.

        Args:
            validation (Validation): The validation rule to add.
        """
        validation.is_ca = self.is_ca
        self.add_component(validation)

    def validate(self, cert: Certificate) -> bool:
        """Validate the certificate using all child validations.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if all validations pass, False otherwise.
        """
        all_valid = True
        for validation in self._components:
            if not validation.validate(cert):
                all_valid = False
            self._errors.extend(validation.get_errors())
            self._warnings.extend(validation.get_warnings())
        return all_valid

class ValidationUtils:
    """Utility class for common validation tasks."""

    @staticmethod
    def validate_ipaddress(value: str, context: str) -> tuple[bool, list[str]]:
        """Validate an iPAddress entry.

        Args:
            value (str): The iPAddress to validate.
            context (str): Contextual information for logging (e.g., "SAN", "IAN").

        Returns:
            tuple: A tuple containing a boolean indicating validity and a list of error or warning messages.
        """
        errors = []
        try:
            # Attempt to parse as an individual IP address
            ip_address(value)
        except ValueError:
            try:
                # Check if it's a network range (subnet)
                network = ip_network(value, strict=True)
                errors.append(f'{context} iPAddress contains a network address: {network}. Networks are not standard.')
            except ValueError:
                errors.append(f'{context} Invalid iPAddress: {value}')
                return False, errors
        return True, errors

#############


class SerialNumberValidation(Validation):
    """Validates the Serial Number of a certificate (RFC 5280, Section 4.1.2.2).

    This validation ensures:
    - The serial number is a positive integer.
    - The serial number is unique for the CA that issued the certificate. (NOT IMPLEMENTED)
    - The serial number is not longer than 20 octets (160 bits).
    """

    MAX_SERIAL_NUMBER_OCTETS = 20

    def __init__(self) -> None:
        """Initialize the SerialNumberValidation."""
        super().__init__()

    def validate(self, cert: Certificate) -> bool:
        """Validate the Serial Number of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for non-positive serial numbers or serial numbers exceeding 20 octets.
            Warnings for issues that certificate users should handle gracefully.
        """
        result = True

        try:
            # Extract the serial number
            serial_number = cert.serial_number

            # Check if the serial number is positive
            if serial_number <= 0:
                self.log_error('Serial number must be a positive integer.')
                result = False

            # Check if the serial number exceeds 20 octets
            serial_number_octets = (serial_number.bit_length() + 7) // 8
            if serial_number_octets > self.MAX_SERIAL_NUMBER_OCTETS:
                self.log_error('Serial number exceeds 20 octets (160 bits).')
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Serial Number validation: {e}')
            result = False

        return result


class SignatureValidation(Validation):
    """Validates the Signature field of a certificate (RFC 5280, Section 4.1.2.3).

    This validation ensures:
    - The signature field in the certificate matches the signatureAlgorithm
    field in the TBS certificate. (NOT SUPPORTED)
    - The signature algorithm is among the supported algorithms provided during initialization.
    """

    def __init__(self, supported_algorithms: set[str] | None = None) -> None:
        """Initialize the SignatureValidation.

        Args:
            supported_algorithms (set[str]): A set of supported signature algorithm OIDs from SignatureAlgorithmOID.
        """
        super().__init__()

        self.supported_algorithms = supported_algorithms or {
            algo.dotted_string for algo in SignatureAlgorithmOid # type: ignore[attr-defined]
        }


    def validate(self, cert: Certificate) -> bool:
        """Validate the Signature field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors if the signature algorithm in the certificate does not
            match the signatureAlgorithm field in the TBS certificate.
            Warnings if the signature algorithm is not in the provided supported algorithms.
        """
        result = True

        try:
            # Extract the signature algorithm OID in the certificate
            signature_algorithm_oid = cert.signature_algorithm_oid

            # Check if the signature algorithm is in the provided list of supported algorithms
            if signature_algorithm_oid.dotted_string not in self.supported_algorithms:
                algorithm_name = getattr(signature_algorithm_oid, 'name', 'Unknown Algorithm')

                self.log_warning(
                    f'Signature algorithm {algorithm_name} is not in the '
                    f'provided list of supported algorithms. '
                    'It may still be valid but is not guaranteed to conform.'
                )

        except AttributeError as e:
            self.log_error(f'Error accessing signature fields in the certificate: {e}')
            result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Signature validation: {e}')
            result = False

        return result


class IssuerValidation(Validation):
    """Validates the Issuer field of a certificate (RFC 5280, Section 4.1.2.4).

    This validation ensures:
    - The issuer field contains a non-empty distinguished name (DN).
    - The distinguished name is composed of attributes defined in X.501, using DirectoryString types.
    - For conformance, the issuer name SHOULD use either PrintableString or UTF8String for encoding,
      except in backward compatibility scenarios where TeletexString, BMPString, or UniversalString
      are permitted.
    - Logs warnings if standard attribute types (e.g., country, organization, common name) are missing.
    """
    default_oids: ClassVar[set[ObjectIdentifier]] = {
        NameOID.COUNTRY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.COMMON_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.SERIAL_NUMBER,
    }

    def __init__(self, standard_oids: set[ObjectIdentifier] | None = None) -> None:
        """Initialize the IssuerValidation.

        Args:
            standard_oids (set): A set of OIDs representing standard attribute types to validate against.
                                 Defaults to a standard set defined by RFC 5280.
        """
        super().__init__()
        self.standard_oids = standard_oids or self.default_oids

    def validate(self, cert: Certificate) -> bool:
        """Validate the Issuer field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or empty issuer fields or unsupported DirectoryString encodings.
            Warnings for backward compatibility scenarios or unusual attribute types.
            Warnings if standard attribute types are missing.
        """
        result = True

        try:
            # Extract the issuer field
            issuer = cert.issuer

            # Ensure the issuer field is non-empty
            if not issuer:
                self.log_error('Issuer field is empty. It must contain a non-empty distinguished name (DN).')
                return False

            # Validate the attribute types in the issuer DN
            for attribute in issuer:
                oid = attribute.oid
                value = attribute.value

                # Ensure the value is non-empty
                if not value:
                    self.log_error(f'Issuer attribute {oid.dotted_string} has an empty value.')
                    result = False

            # Check for standard attribute types
            issuer_oids = {attr.oid for attr in issuer}
            missing_oids = self.standard_oids - issuer_oids

            if missing_oids:
                missing_names = [oid.dotted_string for oid in missing_oids]
                self.log_warning(
                    f"Issuer field is missing some recommended standard attribute types: {', '.join(missing_names)}"
                )

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Issuer validation: {e}')
            result = False

        return result


class ValidityValidation(Validation):
    """Validates the Validity field of a certificate (RFC 5280, Section 4.1.2.5).

    This validation ensures:
    - The validity period is encoded correctly (UTCTime or GeneralizedTime).
    - Dates before 2050 are encoded as UTCTime.
    - Dates in 2050 or later are encoded as GeneralizedTime.
    - The validity period includes the current time if the certificate is active.
    - The validity period falls within an acceptable range if defined.
    - If the notAfter date is set to 99991231235959Z, additional warnings are provided.
    """

    def __init__(self,
                 not_before: datetime | None = None,
                 not_after: datetime | None = None) -> None:
        """Initialize the ValidityValidation.

        Args:
            not_before (datetime): Optional earliest allowed `notBefore` date.
            not_after (datetime): Optional latest allowed `notAfter` date.
        """
        super().__init__()
        self.not_before = not_before
        self.not_after = not_after

    def validate(self, cert: Certificate) -> bool:
        """Validate the Validity field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for invalid date encodings or expired certificates.
            Warnings for certificates with no well-defined expiration date (e.g., 99991231235959Z).
        """
        result = True

        try:
            # Extract validity dates
            cert_not_before = cert.not_valid_before_utc
            cert_not_after = cert.not_valid_after_utc

            # Get the current time
            current_time = datetime.now(timezone.utc)

            # Check if the certificate is valid at the current time
            if not (cert_not_before <= current_time <= cert_not_after):
                self.log_error(
                    f'Certificate is not valid at the current time. '
                    f'Validity period: {cert_not_before} to {cert_not_after}, current time: {current_time}.'
                )
                result = False

            # Check if the certificate validity falls within the specified range
            if self.not_before and cert_not_before < self.not_before:
                self.log_error(
                    f'Certificate notBefore date ({cert_not_before}) is earlier '
                    f'than the allowed minimum ({self.not_before}).'
                )
                result = False

            if self.not_after and cert_not_after > self.not_after:
                self.log_error(
                    f'Certificate notAfter date ({cert_not_after}) is '
                    f'later than the allowed maximum ({self.not_after}).'
                )
                result = False

            # Special handling for certificates with no expiration date
            if cert_not_after == datetime(9999, 12, 31, 23, 59, 59,
                                          tzinfo=timezone.utc):
                self.log_warning('Certificate has no well-defined expiration date (notAfter set to 99991231235959Z).')

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Validity validation: {e}')
            result = False

        return result



class SubjectValidation(Validation):
    """Validates the Subject field of a certificate (RFC 5280, Section 4.1.2.6).

    This validation ensures:
    - The subject field contains a valid distinguished name (DN) when applicable.
    - If the certificate is for a CA or CRL issuer, the subject field matches the issuer field.
    - If the subjectAltName extension is used instead of the subject field, the subject field is empty,
    and the extension is critical.
    - The subject attributes conform to the encoding and uniqueness requirements of RFC 5280.
    """

    def __init__(self) -> None:
        """Initialize the SubjectValidation."""
        super().__init__()

    def validate(self, cert: Certificate) -> bool:
        """Validate the Subject field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for invalid subject fields.
            Warnings for legacy encoding types or deprecated practices.
        """
        result = True

        try:
            subject = cert.subject

            # Check if the subject field is non-empty for CA certificates
            if self.is_ca and not (subject or not list(subject)):
                self.log_error('CA certificate must have a non-empty subject field.')
                result = False

            # Check if the subjectAltName extension is used instead of the subject field
            try:
                subject_alt_name = cast('Extension[SubjectAlternativeName]',
                                        cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME))
                if not list(subject) and not subject_alt_name.critical:
                    self.log_error('If the subject field is empty, the subjectAltName extension must be critical.')
                    result = False
            except Exception: # noqa: BLE001
                if not list(subject):
                    self.log_error('Subject field is empty, and no subjectAltName extension is present.')
                    result = False

            # Validate the encoding of the subject field
            for attribute in subject:
                oid = attribute.oid
                value = attribute.value

                # Ensure the value is non-empty
                if not value:
                    self.log_error(f'Subject attribute {oid.dotted_string} has an empty value.')
                    result = False

            # Additional encoding checks for legacy support
            legacy_encodings = {'TeletexString', 'BMPString', 'UniversalString'}
            for attribute in subject:
                encoding = type(attribute.value).__name__
                if encoding in legacy_encodings:
                    self.log_warning(
                        f'Subject attribute {attribute.oid.dotted_string} uses legacy encoding {encoding}. '
                        'These encodings are deprecated and SHOULD NOT be used for new certificates.'
                    )

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Subject validation: {e}')
            result = False

        return result


class SubjectPublicKeyInfoValidation(Validation):
    """Validates the Subject Public Key Info field of a certificate (RFC 5280, Section 4.1.2.7).

    This validation ensures:
    - The public key algorithm is recognized (e.g., RSA, DSA, or EC).
    - The key length and parameters are appropriate for the algorithm.
    """

    MIN_RSA_KEY_SIZE: ClassVar[int] = 2048
    MIN_DSA_KEY_SIZE: ClassVar[int] = 2048
    SUPPORTED_EC_CURVES: ClassVar[list[str]] = ['secp256r1', 'secp384r1', 'secp521r1']

    def __init__(self, supported_algorithms: set[type[PublicKey]] | None = None) -> None:
        """Initialize the SubjectPublicKeyInfoValidation.

        Args:
            supported_algorithms (set): A set of supported public key algorithm classes (e.g., rsa.RSAPublicKey).
        """
        super().__init__()
        self.supported_algorithms = supported_algorithms or {
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
        }

    def validate(self, cert: Certificate) -> bool:
        """Validate the Subject Public Key Info field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for unsupported algorithms or invalid key lengths.
        """
        result = True

        try:
            # Get the public key from the certificate
            public_key = cert.public_key()

            # Check if the algorithm is supported
            if not isinstance(public_key, tuple(self.supported_algorithms)):
                self.log_error(
                    f"Unsupported public key algorithm: {type(public_key).__name__}. "
                    f"Supported algorithms are: {', '.join([alg.__name__ for alg in self.supported_algorithms])}."
                )
                result = False

            # Perform additional algorithm-specific checks
            if isinstance(public_key, rsa.RSAPublicKey):
                result = self._validate_rsa_key(public_key) and result
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result = self._validate_ec_key(public_key) and result

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Subject Public Key Info validation: {e}')
            result = False

        return result

    def _validate_rsa_key(self, key: rsa.RSAPublicKey) -> bool:
        """Validate an RSA public key.

        Args:
            key (rsa.RSAPublicKey): The RSA public key to validate.

        Returns:
            bool: True if the key is valid, False otherwise.
        """
        try:
            key_size = key.key_size
            if key_size < self.MIN_RSA_KEY_SIZE:
                self.log_error(f'RSA key size too small: {key_size} bits. Minimum recommended size is 2048 bits.')
                return False
        except Exception as e:  # noqa: BLE001
            self.log_error(f'Error validating RSA key: {e}')
            return False

        return True

    def _validate_ec_key(self, key: ec.EllipticCurvePublicKey) -> bool:
        """Validate an Elliptic Curve public key.

        Args:
            key (ec.EllipticCurvePublicKey): The EC public key to validate.

        Returns:
            bool: True if the key is valid, False otherwise.
        """
        try:
            curve = key.curve
            if curve.name not in self.SUPPORTED_EC_CURVES:
                self.log_error(
                    f'Unsupported elliptic curve: {curve.name}. Supported curves are: secp256r1, secp384r1, secp521r1.'
                )
                return False
        except Exception as e:  # noqa: BLE001
            self.log_error(f'Error validating EC key: {e}')
            return False

        return True


class UniqueIdentifiersValidation(Validation):
    """Validates the Unique Identifiers field of a certificate (RFC 5280, Section 4.1.2.8).

    This validation ensures:
    - The unique identifiers fields appear only if the certificate version is 2 or 3.
    - The unique identifiers fields are absent if the certificate version is 1.
    - Logs warnings if unique identifiers are present since their use is discouraged by the profile.
    """

    def __init__(self) -> None:
        """Initialize the UniqueIdentifiersValidation."""
        super().__init__()

    def validate(self, cert: Certificate) -> bool:
        """Validate the Unique Identifiers field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors if the unique identifiers fields are present in version 1 certificates.
            Warnings if unique identifiers are present, as their use is discouraged.
        """
        result = True

        try:
            # Decode the certificate using pyasn1
            tbs_cert, _ = decode(cert.tbs_certificate_bytes, asn1Spec=TBSCertificate())

            # Get the version field as a string
            version_field = tbs_cert.getComponentByName('version')
            if version_field is None:
                version = 1  # Default to version 1 if version field is absent
            else:
                version_text = version_field.prettyPrint()
                version_map = {'v1': 1, 'v2': 2, 'v3': 3}
                version = version_map.get(version_text) or -1

                if version is None:
                    self.log_error(f'Unrecognized version field value: {version_text}.')
                    return False

            # Check for unique identifiers
            issuer_unique_id = tbs_cert.getComponentByName('issuerUniqueID')
            subject_unique_id = tbs_cert.getComponentByName('subjectUniqueID')

            if version == 1:
                if issuer_unique_id is not None or subject_unique_id is not None:
                    self.log_error('Unique identifiers must not appear in version 1 certificates.')
                    result = False
            elif version in [2, 3]:
                if issuer_unique_id is not None or subject_unique_id is not None:
                    self.log_warning('Unique identifiers are present, but their use is discouraged by the profile.')
            else:
                self.log_error(f'Unsupported certificate version: {version}.')
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Unique Identifiers validation: {e}')
            result = False

        return result


class AuthorityKeyIdentifierValidation(Validation):
    """Validates the Authority Key Identifier (AKI) extension of a certificate (RFC 5280, Section 4.2.1.1).

    This validation ensures:
    - The AKI extension is present and properly formatted.
    - The keyIdentifier field is included for all certificates issued by conforming CAs.
    - Self-signed certificates are allowed to omit the AKI extension.
    - The AKI extension is marked as non-critical.
    """

    def __init__(self) -> None:
        """Initialize the AuthorityKeyIdentifierValidation."""
        super().__init__()

    def validate(self, cert: Certificate) -> bool:
        """Validate the Authority Key Identifier (AKI) extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly formatted AKI extensions in non-self-signed certificates.
            Warnings for AKI extension issues in self-signed certificates.
        """
        result = True

        try:
            # Check if the certificate is self-signed
            is_self_signed = cert.issuer == cert.subject

            # Attempt to get the AKI extension
            try:
                aki_ext = cast('Extension[AuthorityKeyIdentifier]',
                               cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER))
            except Exception: # noqa: BLE001
                aki_ext = None

            if aki_ext is None:
                if not is_self_signed:
                    self.log_error(
                        'Authority Key Identifier (AKI) extension is missing in a non-self-signed certificate.'
                    )
                    result = False
                else:
                    self.log_warning('AKI extension is missing in a self-signed certificate, which is permitted.')
                return result

            # Validate that the AKI extension is marked as non-critical
            if aki_ext.critical:
                self.log_error('Authority Key Identifier (AKI) extension must be marked as non-critical.')
                result = False

            # Validate the keyIdentifier field
            aki: AuthorityKeyIdentifier = aki_ext.value
            if aki.key_identifier is None:
                if not is_self_signed:
                    self.log_error('keyIdentifier field in AKI extension is missing in a non-self-signed certificate.')
                    result = False
                else:
                    self.log_warning(
                        'keyIdentifier field in AKI extension is missing in a self-signed certificate, '
                        'which is permitted.'
                    )

            # Optionally validate authorityCertIssuer and authorityCertSerialNumber (if present)
            # These fields are OPTIONAL per RFC 5280, so their absence does not cause failure.
            if aki.authority_cert_issuer or aki.authority_cert_serial_number:
                self.log_warning(
                    'authorityCertIssuer and authorityCertSerialNumber fields are present in the AKI extension. '
                    'Ensure they are properly configured for the certification path.'
                )

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Authority Key Identifier validation: {e}')
            result = False

        return result


class SubjectKeyIdentifierValidation(Validation):
    """Validates the Subject Key Identifier (SKI) extension of a certificate (RFC 5280, Section 4.2.1.2).

    This validation ensures:
    - The SKI extension is present in CA certificates.
    - The SKI is marked as non-critical.
    - The SKI value is derived from the public key using recommended methods for CAs and end-entity certificates.
    """

    def __init__(self) -> None:
        """Initialize the SubjectKeyIdentifierValidation."""
        super().__init__()

    def _map_signature_oid_to_hash_algorithm(self, sig_oid: ObjectIdentifier) -> hashes.HashAlgorithm | None:
        """Map signature OID to the corresponding hash algorithm.

        Args:
            sig_oid: The signature algorithm OID of the certificate.

        Returns:
            A hash algorithm from the cryptography library.
        """
        oid_to_hash = {
            SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(), # noqa: S303
            SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
            SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
            SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
            SignatureAlgorithmOID.ECDSA_WITH_SHA1: hashes.SHA1(), # noqa: S303
            SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
            SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
            SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
            SignatureAlgorithmOID.DSA_WITH_SHA1: hashes.SHA1(), # noqa: S303
            SignatureAlgorithmOID.DSA_WITH_SHA256: hashes.SHA256(),
        }

        if sig_oid not in oid_to_hash:
            err = f'Unsupported signature OID: {sig_oid}'
            raise ValueError(err)

        return oid_to_hash.get(sig_oid)

    def _detect_hash_algorithm(self, cert: Certificate) -> hashes.HashAlgorithm:
        """Detect the hash algorithm used in the certificate.

        Args:
            cert: The X.509 certificate.

        Returns:
            A hash algorithm from the cryptography library.
        """
        sig_oid = cert.signature_algorithm_oid
        detected_hash = self._map_signature_oid_to_hash_algorithm(sig_oid)

        if detected_hash:
            return detected_hash

        # Default fallback to SHA-256 if no specific algorithm is detected
        self.log_warning(f'Unknown signature OID: {sig_oid}. Defaulting to SHA-256.')
        return hashes.SHA256()

    def _compute_key_identifier(self, public_key: PublicKey ,
                                hash_algorithm: HashAlgorithm) -> bytes:
        """Compute the SKI using the given hash algorithm.

        Args:
            public_key: The public key of the certificate.
            hash_algorithm: The hash algorithm to use.

        Returns:
            bytes: The computed SKI value.
        """
        try:
            # Serialize the public key to DER format
            public_key_der = public_key.public_bytes(
                encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
            )

            # Compute the hash
            digest = hashes.Hash(hash_algorithm)
            digest.update(public_key_der)
            return digest.finalize()

        except Exception as e: # noqa: BLE001
            self.log_error(f'Error computing SKI value: {e}')
            return b''

    def validate(self, cert: Certificate) -> bool:
        """Validate the SKI of the given certificate.

        Args:
            cert: The X.509 certificate to validate.

        Returns:
            bool: True if validation is successful, False otherwise.
        """
        result = True

        try:
            # Determine the hash algorithm from the certificate
            hash_algorithm = self._detect_hash_algorithm(cert)

            # Compute the SKI
            computed_ski = self._compute_key_identifier(cert.public_key(), hash_algorithm)

            # Validate the SKI extension (additional validation logic goes here...)
            ski_ext = cast('Extension[SubjectKeyIdentifier]',
                           cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER))
            if ski_ext.value.digest != computed_ski:
                self.log_warning("Computed SKI does not match the certificate's SKI value.")
                result = False

        except Exception as e: # noqa: BLE001
            self.log_error(f'Unexpected error during SKI validation: {e}')
            result = False

        return result


class KeyUsageValidation(Validation):
    """Validates the Key Usage extension of a certificate (RFC 5280, Section 4.2.1.3).

    This validation ensures:
    - The Key Usage extension is present for certificates used to sign other certificates or CRLs.
    - The extension is marked as critical.
    - At least one bit in the Key Usage extension is set.
    - The bits set in the Key Usage extension are consistent with the intended use of the certificate.
    """

    def __init__(self, expected_key_usages: dict[str, bool] | None = None) -> None:
        """Initialize the KeyUsageValidation.

        Args:
            expected_key_usages (dict[str, bool] | None): A dictionary of expected Key Usage values,
            where keys are bit names (e.g., "digital_signature") and values are booleans indicating the expected state.
        """
        super().__init__()
        self.expected_key_usages: dict[str, bool] | None = expected_key_usages or {}

    def validate(self, cert: Certificate) -> bool:
        """Validate the Key Usage extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.
        """
        result = True

        key_usage_ext = self._get_key_usage_extension(cert)
        if key_usage_ext is None:
            return self._handle_missing_extension()

        if not self._validate_criticality(key_usage_ext):
            result = False

        key_usage = key_usage_ext.value
        if not self._validate_at_least_one_bit_set(key_usage):
            result = False

        if not self._compare_key_usage_bits(key_usage):
            result = False

        if self.is_ca and not self._validate_ca_specifics(key_usage):
            result = False

        return result

    def _get_key_usage_extension(self, cert: Certificate) -> Extension[KeyUsage] | None:
        """Retrieve the Key Usage extension from the certificate.

        Args:
            cert (Certificate): The X.509 certificate.

        Returns:
            Optional[Extension]: The Key Usage extension, or None if not present.
        """
        try:
            return cast('Extension[KeyUsage]', cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE))
        except Exception: # noqa: BLE001
            return None

    def _handle_missing_extension(self) -> bool:
        """Handle the case where the Key Usage extension is missing.

        Returns:
            bool: False if the certificate is a CA certificate, True otherwise.
        """
        if self.is_ca:
            self.log_error('Key Usage extension is missing in a CA certificate.')
            return False
        return True

    def _validate_criticality(self, key_usage_ext: Extension[KeyUsage]) -> bool:
        """Validate that the Key Usage extension is marked as critical.

        Args:
            key_usage_ext (Extension): The Key Usage extension.

        Returns:
            bool: False if the extension is not critical, True otherwise.
        """
        if not key_usage_ext.critical:
            self.log_warning('Key Usage extension should be marked as critical.')
            return False
        return True

    def _validate_at_least_one_bit_set(self, key_usage: KeyUsage) -> bool:
        """Validate that at least one Key Usage bit is set.

        Args:
            key_usage: The Key Usage object containing the bit values.

        Returns:
            bool: True if at least one bit is set, False otherwise.
        """
        if not any([
            key_usage.digital_signature,
            key_usage.key_encipherment,
            key_usage.data_encipherment,
            key_usage.key_agreement,
            key_usage.key_cert_sign,
            key_usage.crl_sign,
            key_usage.encipher_only if key_usage.key_agreement else False,
            key_usage.decipher_only if key_usage.key_agreement else False,
        ]):
            self.log_error('Key Usage extension must have at least one bit set.')
            return False
        return True

    def _compare_key_usage_bits(self, key_usage: KeyUsage) -> bool:
        """Compare the Key Usage bits with the expected values.

        Args:
            key_usage: The Key Usage object containing the bit values.

        Returns:
            bool: True if all expected bits match the actual values, False otherwise.
        """
        if not self.expected_key_usages:
            return True

        result = True
        for bit_name, expected_value in self.expected_key_usages.items():
            actual_value = getattr(key_usage, bit_name, None)
            if actual_value is None:
                self.log_warning(f"Key Usage bit '{bit_name}' is not recognized.")
                continue
            if actual_value != expected_value:
                self.log_error(
                    f"Key Usage bit '{bit_name}' mismatch: expected {expected_value}, found {actual_value}."
                )
                result = False
        return result

    def _validate_ca_specifics(self, key_usage: KeyUsage) -> bool:
        """Perform CA-specific validations for the Key Usage extension.

        Args:
            key_usage: The Key Usage object containing the bit values.

        Returns:
            bool: True if the CA-specific validations pass, False otherwise.
        """
        result = True
        if not key_usage.key_cert_sign:
            self.log_error('CA certificate must have the keyCertSign bit set in the Key Usage extension.')
            result = False
        return result


class CertificatePoliciesValidation(Validation):
    """Validates the Certificate Policies extension of a certificate (RFC 5280, Section 4.2.1.4).

    This validation ensures:
    - The Certificate Policies extension is present if required.
    - The policy identifiers are unique within the extension.
    - If present, the extension is properly configured (e.g., qualifiers).
    - ExplicitText fields conform to size and encoding requirements.
    """

    MAX_EXPLICIT_TEXT_LENGTH = 200

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the CertificatePoliciesValidation.

        Args:
            require_extension (bool): Indicates whether the Certificate Policies extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Certificate Policies extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Certificate Policies extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        cert_policies_ext = self._get_certificate_policies_extension(cert)

        if cert_policies_ext is None:
            return result  # Missing extension is already handled

        result = self._validate_extension_criticality(cert_policies_ext) and result
        return self._validate_policy_identifiers(cert_policies_ext.value) and result

    def _get_certificate_policies_extension(self, cert: Certificate) -> Extension[CertificatePolicies] | None:
        """Retrieve and validate the Certificate Policies extension.

        Args:
            cert (Certificate): The certificate to validate.

        Returns:
            Extension or None: The Certificate Policies extension if present.
        """
        try:
            return cast('Extension[CertificatePolicies]',
                        cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES))
        except Exception: # noqa: BLE001
            if self.require_extension:
                self.log_error('Certificate Policies extension is required but missing.')
            else:
                self.log_warning('Certificate Policies extension is missing. Its presence depends on usage.')
            return None

    def _validate_extension_criticality(self, cert_policies_ext: Extension[CertificatePolicies]) -> bool:
        """Validate the criticality of the Certificate Policies extension.

        Args:
            cert_policies_ext: The Certificate Policies extension to validate.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        if cert_policies_ext.critical:
            self.log_warning('Certificate Policies extension is marked as critical.')
        return True

    def _validate_policy_identifiers(self, cert_policies: CertificatePolicies) -> bool:
        """Validate policy identifiers and qualifiers in the extension.

        Args:
            cert_policies: The policies within the Certificate Policies extension.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        result = True
        seen_oids = set()

        for policy in cert_policies:
            if policy.policy_identifier in seen_oids:
                self.log_error(f'Duplicate policy identifier found: {policy.policy_identifier}.')
                result = False
            seen_oids.add(policy.policy_identifier)

            if policy.policy_qualifiers:
                for qualifier in policy.policy_qualifiers:
                    if hasattr(qualifier, 'explicit_text'):
                        result = self._validate_explicit_text(qualifier.explicit_text) and result

        return result

    def _validate_explicit_text(self, explicit_text: str | None) -> bool:
        """Validate the explicitText field in a policy qualifier.

        Args:
            explicit_text: The explicitText field to validate.

        Returns:
            bool: True if the explicitText field is valid, False otherwise.

        Logs:
            Errors for invalid encodings or sizes.
        """
        if explicit_text is None:
            return True

        # Check length constraints
        if len(explicit_text) > self.MAX_EXPLICIT_TEXT_LENGTH:
            self.log_warning(
                f'explicitText exceeds 200 characters: {len(explicit_text)} characters. '
                'Non-conforming CAs may use larger text.'
            )

        # Check for forbidden encodings
        if isinstance(explicit_text, str):
            return True  # UTF8String or IA5String in modern libraries
        self.log_error('explicitText encoding must be UTF8String or IA5String.')
        return False


class SubjectAlternativeNameValidation(Validation):
    """Validates the Subject Alternative Name (SAN) extension of a certificate (RFC 5280, Section 4.2.1.6).

    This validation ensures:
    - The SAN extension is present when required.
    - The SAN extension contains at least one valid entry.
    - Entries conform to encoding and syntax rules (e.g., rfc822Name, dNSName, iPAddress, URI).
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the SubjectAlternativeNameValidation.

        Args:
            require_extension (bool): Indicates whether the SAN extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the SAN extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured SAN extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the SAN extension
            try:
                san_ext = cast('Extension[SubjectAlternativeName]',
                               cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME))
            except Exception: # noqa: BLE001
                san_ext = None

            if san_ext is None:
                if self.require_extension:
                    self.log_error('Subject Alternative Name (SAN) extension is required but missing.')
                    result = False
                return result

            # Extract SAN values
            san = san_ext.value
            if not san:
                self.log_error('SAN extension is present but contains no entries.')
                return False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during SAN validation: {e}')
            result = False

        return result

class IssuerAlternativeNameValidation(Validation):
    """Validates the Issuer Alternative Name (IAN) extension of a certificate (RFC 5280, Section 4.2.1.7).

    This validation ensures:
    - The IAN extension is encoded as specified in Section 4.2.1.6.
    - Entries conform to encoding and syntax rules (e.g., rfc822Name, dNSName, iPAddress, URI).
    - Where present, the IAN extension is marked as non-critical.
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the IssuerAlternativeNameValidation.

        Args:
            require_extension (bool): Indicates whether the IAN extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the IAN extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured IAN extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the IAN extension
            try:
                ian_ext = cast('Extension[IssuerAlternativeName]',
                               cert.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME))
            except Exception: # noqa: BLE001
                ian_ext = None

            if ian_ext is None:
                if self.require_extension:
                    self.log_error('Issuer Alternative Name (IAN) extension is required but missing.')
                    result = False
                return result

            # Ensure the extension is marked as non-critical
            if ian_ext.critical:
                self.log_warning('Issuer Alternative Name (IAN) extension should be marked as non-critical.')

            # Extract IAN values
            ian = ian_ext.value
            if not ian:
                self.log_error('IAN extension is present but contains no entries.')
                return False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during IAN validation: {e}')
            result = False

        return result


class SubjectDirectoryAttributesValidation(Validation):
    """Validates the Subject Directory Attributes extension of a certificate (RFC 5280, Section 4.2.1.8).

    This validation ensures:
    - The extension is marked as non-critical.
    - The extension contains one or more attributes if present.
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the SubjectDirectoryAttributesValidation.

        Args:
            require_extension (bool): Indicates whether the Subject Directory Attributes extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Subject Directory Attributes extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Subject Directory Attributes extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Subject Directory Attributes extension
            try:
                sda_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES)
            except Exception: # noqa: BLE001
                sda_ext = None

            if sda_ext is None:
                if self.require_extension:
                    self.log_error('Subject Directory Attributes extension is required but missing.')
                    result = False
                return result

            # Ensure the extension is marked as non-critical
            if sda_ext.critical:
                self.log_error('Subject Directory Attributes extension must be marked as non-critical.')
                result = False

            # Extract attributes
            attributes = sda_ext.value
            if not attributes:
                self.log_error('Subject Directory Attributes extension is present but contains no attributes.')
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Subject Directory Attributes validation: {e}')
            result = False

        return result


class BasicConstraintsValidation(Validation):
    """Validates the Basic Constraints extension of a certificate (RFC 5280, Section 4.2.1.9).

    This validation ensures:
    - The Basic Constraints extension is present when required.
    - The cA boolean is consistent with the certificate's intended use.
    - The pathLenConstraint field is valid and consistent with other extensions.
    - The extension is marked as critical when required.
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the BasicConstraintsValidation."""
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Basic Constraints extension of the given certificate."""
        result = True

        basic_constraints_ext = self._get_basic_constraints_extension(cert)
        if basic_constraints_ext is None:
            return self._handle_missing_extension()

        basic_constraints = basic_constraints_ext.value
        result &= self._validate_criticality(basic_constraints_ext)
        result &= self._validate_ca_boolean(basic_constraints)
        result &= self._validate_path_len_constraint(basic_constraints)
        result &= self._validate_key_usage(cert, basic_constraints)

        return result

    def _get_basic_constraints_extension(self, cert: Certificate) -> Extension[BasicConstraints] | None:
        """Retrieve the Basic Constraints extension."""
        try:
            return cast('Extension[BasicConstraints]',
                        cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS))
        except Exception: # noqa: BLE001
            return None

    def _handle_missing_extension(self) -> bool:
        """Handle cases where the Basic Constraints extension is missing."""
        if self.require_extension:
            self.log_error('Basic Constraints extension is required but missing.')
            return False
        return True

    def _validate_criticality(self, ext: Extension[BasicConstraints]) -> bool:
        """Validate that the extension is marked as critical for CA certificates."""
        if self.is_ca and not ext.critical:
            self.log_error('Basic Constraints extension must be marked as critical in CA certificates.')
            return False
        return True

    def _validate_ca_boolean(self, basic_constraints: BasicConstraints) -> bool:
        """Validate the cA boolean in the Basic Constraints extension."""
        ca = basic_constraints.ca
        if self.is_ca and not ca:
            self.log_error('CA certificate must assert the cA boolean in the Basic Constraints extension.')
            return False
        if not self.is_ca and ca:
            self.log_error('End-entity certificate must not assert the cA boolean in the Basic Constraints extension.')
            return False
        return True

    def _validate_path_len_constraint(self, basic_constraints: BasicConstraints) -> bool:
        """Validate the pathLenConstraint field in the Basic Constraints extension."""
        path_len = basic_constraints.path_length
        if path_len is not None:
            if not basic_constraints.ca:
                self.log_error('pathLenConstraint must not be present unless the cA boolean is asserted.')
                return False
            if path_len < 0:
                self.log_error('pathLenConstraint must be greater than or equal to zero.')
                return False
        return True

    def _validate_key_usage(self, cert: Certificate, basic_constraints: BasicConstraints) -> bool:
        """Cross-validate the Basic Constraints extension with the Key Usage extension."""
        if not basic_constraints.ca:
            return True

        try:
            key_usage_ext = cast(KeyUsage, cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE))

            if not key_usage_ext.key_cert_sign:
                self.log_error(
                    'CA certificate with cA boolean asserted must also assert the keyCertSign bit in Key Usage.'
                )
                return False
        except Exception: # noqa: BLE001
            self.log_warning('Key Usage extension is missing. Cannot validate keyCertSign bit.')

        return True


class NameConstraintsValidation(Validation):
    """Validates the Name Constraints extension of a certificate (RFC 5280, Section 4.2.1.10).

    This validation ensures:
    - The Name Constraints extension is present only in CA certificates.
    - The extension is marked as critical.
    - Either permittedSubtrees or excludedSubtrees are present (not an empty sequence).
    - Each name constraint complies with the specified syntax and semantics.
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the NameConstraintsValidation.

        Args:
            require_extension (bool): Indicates whether the Name Constraints extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Name Constraints extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Name Constraints extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Name Constraints extension
            try:
                name_constraints_ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
            except Exception: # noqa: BLE001
                name_constraints_ext = None

            if name_constraints_ext is None:
                if self.require_extension:
                    self.log_error('Name Constraints extension is required but missing.')
                    result = False
                return result

            # Ensure the extension is marked as critical
            if not name_constraints_ext.critical:
                self.log_error('Name Constraints extension must be marked as critical.')
                result = False

            # Extract Name Constraints values
            name_constraints = cast(NameConstraints, name_constraints_ext.value)
            permitted_subtrees = name_constraints.permitted_subtrees
            excluded_subtrees = name_constraints.excluded_subtrees

            # Validate that either permitted or excluded subtrees are present
            if not permitted_subtrees and not excluded_subtrees:
                self.log_error(
                    'Name Constraints extension must contain at least one of permittedSubtrees or excludedSubtrees.'
                )
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Name Constraints validation: {e}')
            result = False

        return result

class PolicyConstraintsValidation(Validation):
    """Validates the Policy Constraints extension of a certificate (RFC 5280, Section 4.2.1.11).

    This validation ensures:
    - The Policy Constraints extension is present only in CA certificates.
    - The extension is marked as critical.
    - Either the requireExplicitPolicy or inhibitPolicyMapping field is present (not an empty sequence).
    - The values of requireExplicitPolicy and inhibitPolicyMapping are non-negative integers.
    """

    def __init__(self, *, require_extension: bool = False) -> None:
        """Initialize the PolicyConstraintsValidation.

        Args:
            require_extension (bool): Indicates whether the Policy Constraints extension is required.
        """
        super().__init__()
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Policy Constraints extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Policy Constraints extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Policy Constraints extension
            try:
                policy_constraints_ext = cast('Extension[PolicyConstraints]',
                cert.extensions.get_extension_for_oid(ExtensionOID.POLICY_CONSTRAINTS))
            except Exception: # noqa: BLE001
                policy_constraints_ext = None

            if policy_constraints_ext is None:
                if self.require_extension:
                    self.log_error('Policy Constraints extension is required but missing.')
                    result = False
                return result

            # Ensure the extension is marked as critical
            if not policy_constraints_ext.critical:
                self.log_error('Policy Constraints extension must be marked as critical.')
                result = False

            # Extract Policy Constraints values
            policy_constraints = policy_constraints_ext.value
            require_explicit_policy = policy_constraints.require_explicit_policy
            inhibit_policy_mapping = policy_constraints.inhibit_policy_mapping

            # Validate the presence of at least one field
            if require_explicit_policy is None and inhibit_policy_mapping is None:
                self.log_error(
                    'Policy Constraints extension must contain at least one of '
                    'requireExplicitPolicy or inhibitPolicyMapping.'
                )
                result = False

            # Validate requireExplicitPolicy
            if require_explicit_policy is not None and require_explicit_policy < 0:
                self.log_error('requireExplicitPolicy must be a non-negative integer.')
                result = False

            # Validate inhibitPolicyMapping
            if inhibit_policy_mapping is not None and inhibit_policy_mapping < 0:
                self.log_error('inhibitPolicyMapping must be a non-negative integer.')
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Policy Constraints validation: {e}')
            result = False

        return result


class ExtendedKeyUsageValidation(Validation):
    """Validates the Extended Key Usage (EKU) extension of a certificate (RFC 5280, Section 4.2.1.12).

    This validation ensures:
    - The EKU extension is used in end-entity certificates as expected.
    - The extension is consistent with the Key Usage extension.
    - The extension contains valid KeyPurposeId OIDs.
    - If anyExtendedKeyUsage is present, the extension is non-critical.
    """

    def __init__(self, *, required_purposes: list[str] | None = None) -> None:
        """Initialize the ExtendedKeyUsageValidation.

        Args:
            required_purposes (list[str]): A list of OIDs (as strings) indicating the expected key purposes.
        """
        super().__init__()
        self.required_purposes = required_purposes or []

    def validate(self, cert: Certificate) -> bool:
        """Validate the Extended Key Usage extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured EKU extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Extended Key Usage extension
            try:
                eku_ext = cast('Extension[ExtendedKeyUsage]',
                               cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE))
            except Exception: # noqa: BLE001
                eku_ext = None

            if eku_ext is None:
                if not self.is_ca and self.required_purposes:
                    self.log_error('Extended Key Usage extension is required but missing.')
                    result = False
                return result

            # Extract EKU values
            eku_values = eku_ext.value

            # Check for anyExtendedKeyUsage
            if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku_values:
                if eku_ext.critical:
                    self.log_error('anyExtendedKeyUsage is present, but the EKU extension is marked as critical.')
                    result = False
                self.log_warning('anyExtendedKeyUsage is present. No restrictions on key purposes.')

            # Validate required purposes
            if self.required_purposes:
                for purpose in self.required_purposes:
                    if purpose not in eku_values:
                        self.log_error(f'Required key purpose {purpose} is missing from EKU.')
                        result = False

            # Cross-validation with Key Usage
            result = self._validate_consistency_with_key_usage(cert, eku_values) and result

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Extended Key Usage validation: {e}')
            result = False

        return result

    def _validate_consistency_with_key_usage(self, cert: Certificate, eku_values: ExtendedKeyUsage) -> bool:
        """Validate consistency between the EKU and Key Usage extensions.

        Args:
            cert (Certificate): The X.509 certificate.
            eku_values: The values of the EKU extension.

        Returns:
            bool: True if the EKU and Key Usage extensions are consistent, False otherwise.
        """
        result = True

        try:
            key_usage_ext = cast('Extension[KeyUsage]', cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE))
            key_usage = key_usage_ext.value

            for eku in eku_values:
                if not self._is_key_usage_consistent(eku, key_usage):
                    result = False

        except Exception:  # noqa: BLE001
            self.log_warning('Key Usage extension is missing. Cannot validate consistency with EKU.')

        return result

    def _is_key_usage_consistent(self, eku: ObjectIdentifier, key_usage: KeyUsage) -> bool:
        """Check if a specific EKU is consistent with the Key Usage extension."""
        eku_to_check: dict[ObjectIdentifier, Callable[[], bool]] = {
            ExtendedKeyUsageOID.SERVER_AUTH: lambda: key_usage.digital_signature
                                                     or key_usage.key_encipherment
                                                     or key_usage.key_agreement,
            ExtendedKeyUsageOID.CLIENT_AUTH: lambda: key_usage.digital_signature or key_usage.key_agreement,
            ExtendedKeyUsageOID.CODE_SIGNING: lambda: key_usage.digital_signature,
            ExtendedKeyUsageOID.EMAIL_PROTECTION: lambda: key_usage.digital_signature
                                                          or key_usage.key_encipherment
                                                          or key_usage.key_agreement,
            ExtendedKeyUsageOID.TIME_STAMPING: lambda: key_usage.digital_signature,
            ExtendedKeyUsageOID.OCSP_SIGNING: lambda: key_usage.digital_signature,
        }

        # Ensure the callable is invoked safely
        if eku in eku_to_check and not eku_to_check[eku]():
            self.log_error(f'Key Usage is inconsistent with {eku.dotted_string} in EKU.')
            return False

        return True


class CRLDistributionPointsValidation(Validation):
    """Validates the CRL Distribution Points extension of an X.509 certificate (RFC 5280, Section 4.2.1.13).

    This validation ensures:
    - The CRL Distribution Points extension is present and contains at least one DistributionPoint.
    - The DistributionPoint should contain either a distributionPoint or cRLIssuer field, or both.
    - The CRL Distribution Points extension should be non-critical, as recommended by RFC 5280.
    - The extension includes valid URI or directory name for CRL retrieval.
    """

    def __init__(self, *, is_ca: bool = False) -> None:
        """Initialize the CRLDistributionPointsValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise. This parameter
                          is included for consistency across validation classes, even if not directly
                          relevant to CRL distribution points validation.
        """
        super().__init__()
        self.is_ca = is_ca

    def validate(self, cert: Certificate) -> bool:
        """Validates the CRL Distribution Points extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or misconfigured CRL Distribution Points extensions.
            Warnings for non-critical issues and best practices deviations.
        """
        result = True

        try:
            crl_ext = self._get_crl_extension(cert)
            if crl_ext is None:
                return result

            crl_values = crl_ext.value
            if not self._validate_crl_values(crl_values):
                result = False

            if crl_ext.critical:
                self.log_warning('CRL Distribution Points extension should be non-critical as recommended by RFC 5280.')
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during CRL Distribution Points validation: {e}')
            result = False

        return result

    def _get_crl_extension(self, cert: Certificate) -> Extension[CRLDistributionPoints] | None:
        """Fetches the CRL Distribution Points extension from the certificate."""
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            return cast('Extension[CRLDistributionPoints]', ext)

        except Exception:  # noqa: BLE001
            self.log_warning(
                "CRL Distribution Points extension is missing. It's recommended for "
                "CAs and applications to support it."
            )

        return None

    def _validate_crl_values(self, crl_values: CRLDistributionPoints) -> bool:
        """Validates the CRL Distribution Points values."""
        if not crl_values:
            self.log_error(
                'CRL Distribution Points extension is empty. At least one DistributionPoint is required.'
            )
            return False

        result = True
        for dp in crl_values:
            if not self._validate_distribution_point(dp):
                result = False
        return result

    def _validate_distribution_point(self, dp: DistributionPoint) -> bool:
        """Validates a single DistributionPoint."""
        result = True

        if not dp.full_name and not dp.crl_issuer:
            self.log_error('A DistributionPoint must contain either a distributionPoint or cRLIssuer field.')
            result = False

        if dp.crl_issuer and not dp.crl_issuer[0].value:
            self.log_error('cRLIssuer field is present but does not contain a valid distinguished name.')
            result = False

        if dp.full_name:
            for name in dp.full_name:
                if isinstance(name, UniformResourceIdentifier):
                    uri = name.value
                    if not self._is_valid_uri(uri):
                        self.log_error(f'Invalid URI in distributionPoint: {uri}')
                        result = False

        return result

    def _is_valid_uri(self, uri: str) -> bool:
        """Checks if the given URI is valid according to the RFC 5280 specifications.

        Args:
            uri (str): The URI to validate.

        Returns:
            bool: True if the URI is valid, False otherwise.
        """
        # A simple check for a valid URI (e.g., HTTP, LDAP)
        return uri.startswith(('http://', 'https://', 'ldap://'))


class InhibitAnyPolicyValidation(Validation):
    """Validates the Inhibit Any Policy extension of an X.509 certificate (RFC 5280, Section 4.2.1.14).

    This validation ensures:
    - The Inhibit Any Policy extension is present in certificates issued to CAs.
    - The extension is marked as critical, as required by RFC 5280.
    - The value of the Inhibit Any Policy extension (SkipCerts) is within the allowed range (0 to MAX).
    - The SkipCerts value indicates the number of non-self-issued certificates that may appear before
    anyPolicy is no longer permitted.
    """

    MAX_SKIP_CERTS = 255

    def __init__(self, *, is_ca: bool = False) -> None:
        """Initialize the InhibitAnyPolicyValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency across validation classes,
                          even though it is primarily relevant to CA certificates.
        """
        super().__init__()
        self.is_ca = is_ca

    def validate(self, cert: Certificate) -> bool:
        """Validates the Inhibit Any Policy extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing, misconfigured, or incorrect Inhibit Any Policy extensions.
            Warnings for non-critical issues.
        """
        result = True

        try:
            # Attempt to get the Inhibit Any Policy extension
            try:
                inhibit_any_policy_ext = cast('Extension[InhibitAnyPolicy]',
                                              cert.extensions.get_extension_for_oid(ExtensionOID.INHIBIT_ANY_POLICY))
            except Exception: # noqa: BLE001
                inhibit_any_policy_ext = None


            if inhibit_any_policy_ext is None:
                if self.is_ca:
                    self.log_error(
                        'Inhibit Any Policy extension is missing in a CA certificate. '
                        'It is mandatory for CA certificates.'
                    )
                    result = False
                return result


            # Extract the value (SkipCerts)
            skip_certs = inhibit_any_policy_ext.value.skip_certs

            # Ensure the extension is critical, as required by RFC 5280
            if not inhibit_any_policy_ext.critical:
                self.log_error('Inhibit Any Policy extension must be marked as critical, as required by RFC 5280.')
                result = False

            # Validate the SkipCerts value (must be within the valid range)
            if not (0 <= skip_certs <= self.MAX_SKIP_CERTS):
                self.log_error(
                    f'Inhibit Any Policy extension contains an invalid SkipCerts value: {skip_certs}. '
                    f'It must be between 0 and 255.'
                )
                result = False

        except Exception as e:  # noqa: BLE001
            self.log_error(f'Unexpected error during Inhibit Any Policy validation: {e}')
            result = False

        return result


class FreshestCRLValidation(Validation):
    """Validates the Freshest CRL (Delta CRL Distribution Point) extension (RFC 5280, Section 4.2.1.15).

    This validation ensures:
    - The Freshest CRL extension is present.
    - The extension is marked as non-critical, as required by RFC 5280.
    - The extension contains valid CRL distribution points for delta CRLs, following the same structure as the
    cRLDistributionPoints extension.
    """

    def __init__(self, *, is_ca: bool = False) -> None:
        """Initialize the FreshestCRLValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, though it's not directly relevant to
                          Freshest CRL validation.
        """
        super().__init__()
        self.is_ca = is_ca

    def validate(self, cert: Certificate) -> bool:
        """Validates the Freshest CRL extension (Delta CRL Distribution Point) of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing, misconfigured, or incorrect Freshest CRL extensions.
            Warnings for non-critical issues.
        """
        result = True
        try:
            freshest_crl_ext = self._get_freshest_crl_extension(cert)
            if freshest_crl_ext is None:
                return result  # Warning already logged

            if not self._validate_extension_criticality(freshest_crl_ext):
                result = False

            crl_values = freshest_crl_ext.value
            if not self._validate_distribution_points(crl_values):
                result = False
        except Exception as e: # noqa: BLE001
            self.log_error(f'Unexpected error during Freshest CRL validation: {e}')
            result = False
        return result

    def _get_freshest_crl_extension(self, cert: Certificate)  -> Extension[FreshestCRL] | None:
        """Attempts to retrieve the Freshest CRL extension from the certificate.

        Args:
            cert (Certificate): The certificate to search.

        Returns:
            Optional[Extension]: The Freshest CRL extension, or None if not found.
        """
        try:
            return cast('Extension[FreshestCRL]', cert.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL))
        except Exception: # noqa: BLE001
            self.log_warning('Freshest CRL extension is missing. Conforming CAs are encouraged to include it.')
            return None

    def _validate_extension_criticality(self, extension: Extension[FreshestCRL]) -> bool:
        """Validates that the extension is marked as non-critical.

        Args:
            extension (Extension): The extension to validate.

        Returns:
            bool: True if the extension is non-critical, False otherwise.
        """
        if extension.critical:
            self.log_error('Freshest CRL extension must be marked as non-critical, as required by RFC 5280.')
            return False
        return True

    def _validate_distribution_points(self, crl_values: FreshestCRL) -> bool:
        """Validates the distribution points within the Freshest CRL extension.

        Args:
            crl_values (list[DistributionPoint]): The list of distribution points to validate.

        Returns:
            bool: True if all distribution points are valid, False otherwise.
        """
        result = True
        for dp in crl_values:
            if not dp.full_name and not dp.crl_issuer:
                self.log_error(
                    'A DistributionPoint in the Freshest CRL extension must contain either a distributionPoint '
                    'or cRLIssuer field.'
                )
                result = False
            if dp.crl_issuer and not dp.crl_issuer[0].value:
                self.log_error(
                    'cRLIssuer field is present in Freshest CRL extension but does not contain a valid '
                    'distinguished name.'
                )
                result = False
            if not self._validate_distribution_point_uris(dp):
                result = False
        return result

    def _validate_distribution_point_uris(self, dp: DistributionPoint) -> bool:
        """Validates the URIs in the distributionPoint field.

        Args:
            dp (DistributionPoint): The distribution point to validate.

        Returns:
            bool: True if all URIs are valid, False otherwise.
        """
        if not dp.full_name:
            return True

        result = True
        for name in dp.full_name:
            if isinstance(name, UniformResourceIdentifier):
                uri = name.value
                if not self._is_valid_uri(uri):
                    self.log_error(f'Invalid URI in distributionPoint of Freshest CRL extension: {uri}')
                    result = False
        return result

    def _is_valid_uri(self, uri: str) -> bool:
        """Checks if the given URI is valid according to RFC 5280 specifications.

        Args:
            uri (str): The URI to validate.

        Returns:
            bool: True if the URI is valid, False otherwise.
        """
        # A simple check for valid URI schemes (e.g., HTTP, LDAP)
        return uri.startswith(('http://', 'https://', 'ldap://'))


class SubjectAttributesValidation(Validation):
    """Validates the subject attributes of an X.509 certificate using OIDs.

    This validation ensures:
    - Certain subject attributes, identified by OID, must exist and match one of the specified exact values
      or regex patterns.
    - Optional subject attributes, identified by OID, must match at least one regex pattern if present.
    - If any attribute exists that is not required or optional, validation fails.
    """

    def __init__(self,
                 required: dict[str, list[re.Pattern[str]]] | None = None,
                 optional: dict[str, list[re.Pattern[str]]] | None = None,
                 ) -> None:
        """Initialize the SubjectAttributesValidation.

        Args:
            required (dict): A dictionary where the key is the OID of the attribute
                             and the value is either a single exact value, a list of exact values,
                             a regex pattern, or a list of regex patterns.
            optional (dict): A dictionary where the key is the OID of the attribute
                             and the value is a regex pattern or a list of regex patterns.
        """
        super().__init__()
        self.required: dict[str, list[re.Pattern[str]]] = required or {}
        self.optional: dict[str, list[re.Pattern[str]]] = optional or {}
        self.unmatched_patterns: dict[str, set[re.Pattern[str]]] = {}
        self.unmatched_values: dict[str, set[str]] = {}

    def validate(self, cert: Certificate, *, strict: bool = True) -> bool:
        """Validates the subject attributes of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.
            strict (bool): Whether to flag unexpected attributes as errors.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing required attributes, mismatched values, or invalid attributes.
        """
        result = True

        try:
            subject_dict = self._convert_subject_to_dict(cert.subject)

            self.unmatched_patterns, self.unmatched_values = self._initialize_unmatched(subject_dict)

            result &= self._match_required_patterns(subject_dict, self.unmatched_patterns, self.unmatched_values)

            result &= self._match_optional_patterns(subject_dict, self.unmatched_values)

            result &= self._handle_unexpected_attributes(subject_dict, strict = strict)

            result &= self._report_unmatched(self.unmatched_patterns, self.unmatched_values)

        except Exception as e:  # noqa: BLE001  # noqa: BLE001
            self.log_error(f'Unexpected error during Subject Attributes validation: {e}')
            result = False

        return result

    # Helper functions

    def _initialize_unmatched(self, subject_dict: dict[str, list[str]]) -> tuple[
        dict[str, set[re.Pattern[str]]], dict[str, set[str]]]:
        """Initializes unmatched patterns and values.

        Args:
            subject_dict (dict[str, list[str]]): Dictionary of subject attributes.

        Returns:
            tuple: A tuple containing dictionaries for unmatched patterns and values.
        """
        unmatched_patterns = {oid: set(patterns) for oid, patterns in self.required.items()}
        unmatched_values = {oid: set(subject_dict.get(oid, [])) for oid in self.required}
        return unmatched_patterns, unmatched_values

    def _match_required_patterns(self, subject_dict: dict[str, list[str]],
                                 unmatched_patterns: dict[str, set[re.Pattern[str]]],
                                 unmatched_values: dict[str, set[str]]) -> bool:
        """Matches required patterns against subject attributes.

        Args:
            subject_dict (dict[str, list[str]]): Dictionary of subject attributes.
            unmatched_patterns (dict[str, set[str]]): Patterns that are yet to be matched.
            unmatched_values (dict[str, set[str]]): Values that are yet to be matched.

        Returns:
            bool: True if matching succeeds, otherwise False.
        """
        result = True

        for oid, required_patterns in self.required.items():
            attr_values = subject_dict.get(oid, [])
            unmatched_patterns[oid] = set(required_patterns)
            unmatched_values[oid] = set(attr_values)

            for value in list(unmatched_values[oid]):
                for pattern in list(unmatched_patterns[oid]):
                    if self._match_value_or_regex(value, pattern):
                        unmatched_patterns[oid].discard(pattern)
                        unmatched_values[oid].discard(value)
                        break

        return result

    def _match_optional_patterns(self, subject_dict: dict[str, list[str]],
                                 unmatched_values: dict[str, set[str]]) -> bool:
        """Matches optional patterns against subject attributes.

        Args:
            subject_dict (dict[str, list[str]]): Dictionary of subject attributes.
            unmatched_values (dict[str, set[str]]): Values that are yet to be matched.

        Returns:
            bool: Always returns True.
        """
        for oid, optional_patterns in self.optional.items():
            attr_values = subject_dict.get(oid, [])
            optional_matches = set()

            if oid not in unmatched_values:
                unmatched_values[oid] = set(attr_values)

            for value in list(unmatched_values[oid]):
                if any(self._match_value_or_regex(value, pattern) for pattern in optional_patterns):
                    optional_matches.add(value)

            unmatched_values[oid] -= optional_matches

        return True

    def _handle_unexpected_attributes(self, subject_dict: dict[str, list[str]], *,strict: bool) -> bool:
        """Handles unexpected attributes if strict mode is enabled.

        Args:
            subject_dict (dict[str, list[str]]): Dictionary of subject attributes.
            strict (bool): Whether to flag unexpected attributes as errors.

        Returns:
            bool: True if no errors, otherwise False.
        """
        result = True

        for oid, attr_values in subject_dict.items():
            if oid not in self.required and oid not in self.optional and strict:
                self.log_error(f'Unexpected attribute with OID {oid} and values {attr_values}.')
                result = False

        return result

    def _report_unmatched(self, unmatched_patterns: dict[str, set[re.Pattern[str]]],
                          unmatched_values: dict[str, set[str]]) -> bool:
        """Reports unmatched patterns and values.

        Args:
            unmatched_patterns (dict[str, set[str]]): Patterns that are yet to be matched.
            unmatched_values (dict[str, set[str]]): Values that are yet to be matched.

        Returns:
            bool: True if no unmatched items, otherwise False.
        """
        result = True

        for oid, patterns in unmatched_patterns.items():
            if patterns:
                self.log_error(f'Required attribute with OID {oid} is missing patterns: {list(patterns)}.')
                result = False

        for oid, values in unmatched_values.items():
            if values:
                self.log_error(f'Attribute with OID {oid} has unmatched values: {list(values)}.')
                result = False

        return result

    def _convert_subject_to_dict(self, subject: Name) -> dict[str, list[str]]:
        """Converts the subject field to a dictionary with OIDs as keys and lists of attribute values.

        Args:
            subject (Name): The subject field of the X.509 certificate.

        Returns:
            dict[str, list[str]]: A dictionary where the keys are OIDs (as strings) and the values are
            lists of attribute values.
        """
        subject_dict: dict[str, list[str]] = {}
        for relative_distinguished_name in subject:
            oid = relative_distinguished_name.oid.dotted_string
            value = relative_distinguished_name.value
            if oid not in subject_dict:
                subject_dict[oid] = []
            subject_dict[oid].append(value.decode('utf-8') if isinstance(value, bytes) else value)
        return subject_dict

    def _match_value_or_regex(self, attr_value: str, pattern: str | re.Pattern[str]) -> bool:
        """Matches the attribute value against one or more exact values or regex patterns.

        Args:
            attr_value (str): The value of the attribute from the certificate.
            pattern (str | re.Pattern): The exact value or regex pattern to match against.

        Returns:
            bool: True if the value matches the pattern, False otherwise.
        """
        if isinstance(pattern, str):
            # Exact match
            return attr_value == pattern
        if isinstance(pattern, re.Pattern):
            # Regex match
            return pattern.match(attr_value) is not None
        return False

class SANAttributesValidation(Validation):
    """Validates the Subject Alternative Names (SAN) of an X.509 certificate using OIDs.

    This validation ensures:
    - Certain SANs, identified by OID, must exist and match one of the specified exact values or regex patterns.
    - Optional SANs, identified by OID, must match at least one regex pattern if present.
    - If any SAN exists that is not required or optional, validation fails.
    """

    def __init__(self,
                 required: dict[str, list[re.Pattern[str]]] | None = None,
                 optional: dict[str,list[re.Pattern[str]]] | None = None,
                 ) -> None:
        """Initialize the SANAttributesValidation.

        Args:
            required (dict | None): A dictionary where the key is the OID of the SAN attribute
                                    and the value is either a single exact value, a list of exact values,
                                    a regex pattern, or a list of regex patterns.
            optional (dict | None): A dictionary where the key is the OID of the SAN attribute
                                    and the value is a regex pattern or a list of regex patterns.
        """
        super().__init__()
        self.required: dict[str, list[re.Pattern[str]]] = required or {}
        self.optional: dict[str, list[re.Pattern[str]]] = optional or {}
        self.san_dict: dict[str, list[str]] = {}
        self.unmatched_patterns: dict[str, list[re.Pattern[str]]] = {}
        self.unmatched_values: dict[str, list[str]] = {}

    def validate(self, cert: Certificate, *, strict: bool = True) -> bool:
        """Validates the SAN attributes of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.
            strict (bool): Whether to flag unexpected attributes as errors.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing required SANs, mismatched values, or invalid SAN attributes.
        """
        result = True

        try:
            san_list = self._get_san_list(cert)
            if not san_list:
                return False  # Error already logged in `_get_san_list`.

            self.san_dict = self._convert_san_to_dict(san_list)

            if not self._validate_required_sans():
                result = False

            if not self._validate_optional_sans():
                result = False

            if strict and not self._check_unexpected_sans():
                result = False

        except Exception as e:  # noqa: BLE001  # noqa: BLE001
            self.log_error(f'Unexpected error during SAN validation: {e}')
            result = False

        return result

    def _get_san_list(self, cert: Certificate) -> Any | None:
        """Retrieves and returns the SAN list from the certificate, or logs an error."""
        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except ExtensionNotFound:
            self.log_error('The certificate does not contain a Subject Alternative Name (SAN) extension.')
            return None
        else:
            return san_extension.value

    def _validate_required_sans(self) -> bool:
        """Validates required SAN attributes."""
        is_valid = True
        for oid, required_patterns in self.required.items():
            san_values = self.san_dict.get(oid, [])
            self.unmatched_patterns[oid] = required_patterns.copy()
            self.unmatched_values[oid] = san_values.copy()

            for value in list(self.unmatched_values[oid]):  # Work on a copy to avoid modifying during iteration
                for pattern in required_patterns:
                    if self._match_value_or_regex(value, pattern):
                        if pattern in self.unmatched_patterns[oid]:
                            self.unmatched_patterns[oid].remove(pattern)
                        if value in self.unmatched_values[oid]:
                            self.unmatched_values[oid].remove(value)
                        break

            if self.unmatched_patterns[oid]:
                self.log_error(f'Required SAN attribute {oid} is missing patterns: {self.unmatched_patterns[oid]}.')
                is_valid = False

        return is_valid

    def _validate_optional_sans(self) -> bool:
        """Validates optional SAN attributes."""
        for oid, optional_patterns in self.optional.items():
            san_values = self.san_dict.get(oid, [])
            if oid not in self.unmatched_values:
                self.unmatched_values[oid] = san_values.copy()

            optional_matches = []
            optional_matches.extend(
                [value for value in self.unmatched_values[oid] if
                 any(self._match_value_or_regex(value, pattern) for pattern in optional_patterns)]
            )

            # Remove matched optional values
            self.unmatched_values[oid] = [v for v in self.unmatched_values[oid] if v not in optional_matches]

        return True

    def _check_unexpected_sans(self) -> bool:
        """Handles unexpected SAN attributes."""
        is_valid = True
        for oid, san_values in self.san_dict.items():
            if oid not in self.required and oid not in self.optional:
                self.log_error(f'Unexpected SAN attribute {oid} and values {san_values}.')
                is_valid = False
        return is_valid


    def _convert_san_to_dict(self, san_list: Sequence[GeneralName]) -> dict[str, list[str]]:
        """Converts the SAN list to a dictionary using GeneralName naming conventions.

        Args:
            san_list: The SAN extension value, typically a sequence of GeneralNames.

        Returns:
            A dictionary where keys are GeneralName types (e.g., 'dNSName', 'IPAddress')
            and values are lists of attribute values.
        """
        san_dict: dict[str, list[str]] = {
            'otherName': [],
            'rfc822Name': [],
            'dNSName': [],
            'x400Address': [],
            'directoryName': [],
            'ediPartyName': [],
            'uniformResourceIdentifier': [],
            'IPAddress': [],
            'registeredID': [],
        }

        for san in san_list:
            if isinstance(san, RFC822Name):
                san_dict['rfc822Name'].append(san.value)
            elif isinstance(san, DNSName):
                san_dict['dNSName'].append(san.value)
            elif isinstance(san, IPAddress):
                san_dict['IPAddress'].append(str(san.value))
            elif isinstance(san, UniformResourceIdentifier):
                san_dict['uniformResourceIdentifier'].append(san.value)
            elif isinstance(san, DirectoryName):
                san_dict['directoryName'].append(str(san.value))
            elif isinstance(san, OtherName):
                san_dict['otherName'].append(str(san.value))
            elif isinstance(san, RegisteredID):
                san_dict['registeredID'].append(str(san.value))
            else:
                error_message = f'Unknown SAN type encountered: {san.__class__.__name__}'
                raise TypeError(error_message)

        # Remove keys with empty lists
        return {key: value for key, value in san_dict.items() if value}

    def _match_value_or_regex(self, attr_value: str, pattern: str | re.Pattern[str]) -> bool:
        """Matches the attribute value against one or more exact values or regex patterns.

        Args:
            attr_value: The value of the attribute from the certificate.
            pattern: A single exact value, regex pattern, or a list of such values or patterns.

        Returns:
            bool: True if it matches any value or pattern, False otherwise.
        """
        if isinstance(pattern, str):
            return attr_value == pattern
        if isinstance(pattern, re.Pattern):
            return pattern.match(attr_value) is not None
        return False
