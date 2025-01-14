import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509 import Certificate, ExtensionNotFound
from cryptography.x509.extensions import AuthorityKeyIdentifier
from cryptography.x509.general_name import (
    DirectoryName,
    DNSName,
    IPAddress,
    OtherName,
    RegisteredID,
    RFC822Name,
    UniformResourceIdentifier,
)
from cryptography.x509.name import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, SignatureAlgorithmOID
from pyasn1.codec.der.decoder import decode
from pyasn1_modules.rfc2459 import TBSCertificate


class Validation(ABC):
    """Abstract base class for a validation rule or composite.
    """

    def __init__(self):
        self._components = []  # List of child validations (leafs or composites)
        self._errors = []  # List of errors encountered during validation
        self._warnings = []  # List of warnings encountered during validation

    @abstractmethod
    def validate(self, cert: Certificate) -> bool:
        """Perform validation on the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.
        """

    def add_component(self, validation: 'Validation'):
        """Add a validation rule or composite to the current validation.

        Args:
            validation (Validation): The validation rule or composite to add.
        """
        self._components.append(validation)

    def get_errors(self) -> list:
        """Get the list of errors encountered during validation.

        Returns:
            list: A list of error messages.
        """
        return self._errors

    def get_warnings(self) -> list:
        """Get the list of warnings encountered during validation.

        Returns:
            list: A list of warning messages.
        """
        return self._warnings

    def log_error(self, message: str):
        """Log an error message.

        Args:
            message (str): The error message to log.
        """
        self._errors.append(message)

    def log_warning(self, message: str):
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

    def __init__(self, is_ca: bool):
        super().__init__()
        self.is_ca = is_ca

    def add_validation(self, validation: Validation):
        """Add a validation rule to the composite.

        Args:
            validation (Validation): The validation rule to add.
        """
        validation.is_ca = self.is_ca  # Ensure the context (CA or non-CA) is passed to leaf validations
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


#############


class SerialNumberValidation(Validation):
    """Validates the Serial Number of a certificate (RFC 5280, Section 4.1.2.2).

    This validation ensures:
    - The serial number is a positive integer.
    - The serial number is unique for the CA that issued the certificate. (NOT IMPLEMENTED)
    - The serial number is not longer than 20 octets (160 bits).
    """

    def __init__(self, is_ca: bool = None):
        """Initialize the SerialNumberValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
        """
        super().__init__()
        self.is_ca = is_ca

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
            if serial_number_octets > 20:
                self.log_error('Serial number exceeds 20 octets (160 bits).')
                result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Serial Number validation: {e}')
            result = False

        return result


class SignatureValidation(Validation):
    """Validates the Signature field of a certificate (RFC 5280, Section 4.1.2.3).

    This validation ensures:
    - The signature field in the certificate matches the signatureAlgorithm field in the TBS certificate. (NOT SUPPORTED)
    - The signature algorithm is among the supported algorithms provided during initialization.
    """

    def __init__(self, is_ca: bool = None, supported_algorithms: set = None):
        """Initialize the SignatureValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, but it does not affect this validation.
            supported_algorithms (set): A set of supported signature algorithm OIDs from SignatureAlgorithmOID.
        """
        super().__init__()
        self.is_ca = is_ca
        self.supported_algorithms = supported_algorithms or {
            SignatureAlgorithmOID.RSA_WITH_SHA256,
            SignatureAlgorithmOID.ECDSA_WITH_SHA256,
            SignatureAlgorithmOID.RSA_WITH_SHA1,
            SignatureAlgorithmOID.ECDSA_WITH_SHA1,
        }

    def validate(self, cert: Certificate) -> bool:
        """Validate the Signature field of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors if the signature algorithm in the certificate does not match the signatureAlgorithm field in the TBS certificate.
            Warnings if the signature algorithm is not in the provided supported algorithms.
        """
        result = True

        try:
            # Extract the signature algorithm OID in the certificate
            signature_algorithm_oid = cert.signature_algorithm_oid

            # Check if the signature algorithm is in the provided list of supported algorithms
            if signature_algorithm_oid not in self.supported_algorithms:
                self.log_warning(
                    f'Signature algorithm {signature_algorithm_oid._name} is not in the provided list of supported algorithms. '
                    'It may still be valid but is not guaranteed to conform.'
                )

        except AttributeError as e:
            self.log_error(f'Error accessing signature fields in the certificate: {e}')
            result = False

        except Exception as e:
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

    def __init__(self, is_ca: bool = None, standard_oids: set = None):
        """Initialize the IssuerValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, but it does not affect this validation.
            standard_oids (set): A set of OIDs representing standard attribute types to validate against.
                                 Defaults to a standard set defined by RFC 5280.
        """
        super().__init__()
        self.is_ca = is_ca
        self.standard_oids = standard_oids or {
            NameOID.COUNTRY_NAME,
            NameOID.ORGANIZATION_NAME,
            NameOID.COMMON_NAME,
            NameOID.STATE_OR_PROVINCE_NAME,
            NameOID.LOCALITY_NAME,
            NameOID.SERIAL_NUMBER,
        }

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

        except Exception as e:
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
    - If the notAfter date is set to 99991231235959Z, additional warnings are provided.
    """

    def __init__(self, is_ca: bool = None):
        """Initialize the ValidityValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, but it does not affect this validation.
        """
        super().__init__()
        self.is_ca = is_ca

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
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            # Get the current time
            current_time = datetime.now(timezone.utc)

            # Check if the certificate is valid at the current time
            if not (not_before <= current_time <= not_after):
                self.log_error(
                    f'Certificate is not valid at the current time. '
                    f'Validity period: {not_before} to {not_after}, current time: {current_time}.'
                )
                result = False

            # Check the encoding of the notBefore and notAfter dates
            # self._validate_date_encoding(not_before, "notBefore") #TODO (FHatCSW): Encoding seems to be handled by cryptography
            # self._validate_date_encoding(not_after, "notAfter") #TODO (FHatCSW): Encoding seems to be handled by cryptography

            # Special handling for certificates with no expiration date
            if not_after == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc):
                self.log_warning('Certificate has no well-defined expiration date (notAfter set to 99991231235959Z).')

        except Exception as e:
            self.log_error(f'Unexpected error during Validity validation: {e}')
            result = False

        return result

    def _validate_date_encoding(self, date: datetime, field_name: str):
        """Validate the encoding of a date (UTCTime or GeneralizedTime).

        Args:
            date (datetime): The date to validate.
            field_name (str): The name of the field being validated (e.g., "notBefore" or "notAfter").

        Logs:
            Errors if the encoding does not conform to RFC 5280 requirements.
        """
        if date.year < 2050:
            if len(date.strftime('%Y')) != 2:
                self.log_error(
                    f'The {field_name} date ({date}) before 2050 must be encoded as UTCTime (YYMMDDHHMMSSZ).'
                )
        elif len(date.strftime('%Y')) != 4:
            self.log_error(
                f'The {field_name} date ({date}) in 2050 or later must be encoded as GeneralizedTime (YYYYMMDDHHMMSSZ).'
            )


class SubjectValidation(Validation):
    """Validates the Subject field of a certificate (RFC 5280, Section 4.1.2.6).

    This validation ensures:
    - The subject field contains a valid distinguished name (DN) when applicable.
    - If the certificate is for a CA or CRL issuer, the subject field matches the issuer field.
    - If the subjectAltName extension is used instead of the subject field, the subject field is empty, and the extension is critical.
    - The subject attributes conform to the encoding and uniqueness requirements of RFC 5280.
    """

    def __init__(self, is_ca: bool = None):
        """Initialize the SubjectValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
        """
        super().__init__()
        self.is_ca = is_ca

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
            if self.is_ca:
                if not subject or not list(subject):
                    self.log_error('CA certificate must have a non-empty subject field.')
                    result = False

            # Check if the subjectAltName extension is used instead of the subject field
            try:
                subject_alt_name = cert.extensions.get_extension_for_oid(NameOID.SUBJECT_ALTERNATIVE_NAME)
                if not list(subject) and not subject_alt_name.critical:
                    self.log_error('If the subject field is empty, the subjectAltName extension must be critical.')
                    result = False
            except Exception:
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

        except Exception as e:
            self.log_error(f'Unexpected error during Subject validation: {e}')
            result = False

        return result


class SubjectPublicKeyInfoValidation(Validation):
    """Validates the Subject Public Key Info field of a certificate (RFC 5280, Section 4.1.2.7).

    This validation ensures:
    - The public key algorithm is recognized (e.g., RSA, DSA, or EC).
    - The key length and parameters are appropriate for the algorithm.
    """

    def __init__(self, is_ca: bool = None, supported_algorithms: set = None):
        """Initialize the SubjectPublicKeyInfoValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, but it does not affect this validation.
            supported_algorithms (set): A set of supported public key algorithm classes (e.g., rsa.RSAPublicKey).
        """
        super().__init__()
        self.is_ca = is_ca
        self.supported_algorithms = supported_algorithms or {
            rsa.RSAPublicKey,
            dsa.DSAPublicKey,
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
            elif isinstance(public_key, dsa.DSAPublicKey):
                result = self._validate_dsa_key(public_key) and result
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                result = self._validate_ec_key(public_key) and result

        except Exception as e:
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
            if key_size < 2048:
                self.log_error(f'RSA key size too small: {key_size} bits. Minimum recommended size is 2048 bits.')
                return False
        except Exception as e:
            self.log_error(f'Error validating RSA key: {e}')
            return False

        return True

    def _validate_dsa_key(self, key: dsa.DSAPublicKey) -> bool:
        """Validate a DSA public key.

        Args:
            key (dsa.DSAPublicKey): The DSA public key to validate.

        Returns:
            bool: True if the key is valid, False otherwise.
        """
        try:
            key_size = key.key_size
            if key_size < 2048:
                self.log_error(f'DSA key size too small: {key_size} bits. Minimum recommended size is 2048 bits.')
                return False
        except Exception as e:
            self.log_error(f'Error validating DSA key: {e}')
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
            if curve.name not in ['secp256r1', 'secp384r1', 'secp521r1']:
                self.log_error(
                    f'Unsupported elliptic curve: {curve.name}. Supported curves are: secp256r1, secp384r1, secp521r1.'
                )
                return False
        except Exception as e:
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

    def __init__(self, is_ca: bool = None):
        """Initialize the UniqueIdentifiersValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, but it does not affect this validation.
        """
        super().__init__()
        self.is_ca = is_ca

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
                version = version_map.get(version_text)

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

        except Exception as e:
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

    def __init__(self, is_ca: bool = None):
        """Initialize the AuthorityKeyIdentifierValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
        """
        super().__init__()
        self.is_ca = is_ca

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
                aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            except Exception:
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
                        'keyIdentifier field in AKI extension is missing in a self-signed certificate, which is permitted.'
                    )

            # Optionally validate authorityCertIssuer and authorityCertSerialNumber (if present)
            # These fields are OPTIONAL per RFC 5280, so their absence does not cause failure.
            if aki.authority_cert_issuer or aki.authority_cert_serial_number:
                self.log_warning(
                    'authorityCertIssuer and authorityCertSerialNumber fields are present in the AKI extension. '
                    'Ensure they are properly configured for the certification path.'
                )

        except Exception as e:
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

    def __init__(self, is_ca: bool = None):
        """Initialize the SubjectKeyIdentifierValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
        """
        super().__init__()
        self.is_ca = is_ca

    def validate(self, cert: Certificate) -> bool:
        """Validate the Subject Key Identifier (SKI) extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing SKI extensions in CA certificates or SKI extensions not marked as non-critical.
            Warnings for mismatched SKI values based on the recommended derivation methods.
        """
        result = True

        try:
            # Attempt to get the SKI extension
            try:
                ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            except Exception:
                ski_ext = None

            if ski_ext is None:
                if self.is_ca:
                    self.log_error('Subject Key Identifier (SKI) extension is missing in a CA certificate.')
                    result = False
                else:
                    self.log_warning('SKI extension is missing in an end-entity certificate, which is permitted.')
                return result

            # Validate that the SKI extension is marked as non-critical
            if ski_ext.critical:
                self.log_error('Subject Key Identifier (SKI) extension must be marked as non-critical.')
                result = False

            # Validate SKI value derivation for CA certificates
            if self.is_ca:
                computed_ski = self._compute_key_identifier(cert.public_key())
                if ski_ext.value.digest != computed_ski:
                    self.log_warning(
                        'SKI value does not match the recommended SHA-1 hash derivation from the public key.'
                    )

        except Exception as e:
            self.log_error(f'Unexpected error during Subject Key Identifier validation: {e}')
            result = False

        return result

    def _compute_key_identifier(self, public_key) -> bytes:
        """Compute the key identifier (SKI) based on the SHA-1 hash of the public key.

        Args:
            public_key: The public key of the certificate.

        Returns:
            bytes: The computed key identifier.
        """
        try:
            # Serialize the public key to DER format
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Compute the SHA-1 hash
            digest = hashes.Hash(hashes.SHA1())
            digest.update(public_key_der)
            return digest.finalize()

        except Exception as e:
            self.log_error(f'Error computing SKI value: {e}')
            return b''


class KeyUsageValidation(Validation):
    """Validates the Key Usage extension of a certificate (RFC 5280, Section 4.2.1.3).

    This validation ensures:
    - The Key Usage extension is present for certificates used to sign other certificates or CRLs.
    - The extension is marked as critical.
    - At least one bit in the Key Usage extension is set.
    - The bits set in the Key Usage extension are consistent with the intended use of the certificate.
    """

    def __init__(self, is_ca: bool = None):
        """Initialize the KeyUsageValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
        """
        super().__init__()
        self.is_ca = is_ca

    def validate(self, cert: Certificate) -> bool:
        """Validate the Key Usage extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Key Usage extensions.
            Warnings for potential inconsistencies in Key Usage bits.
        """
        result = True

        try:
            # Attempt to get the Key Usage extension
            try:
                key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            except Exception:
                key_usage_ext = None

            if key_usage_ext is None:
                if self.is_ca:
                    self.log_error('Key Usage extension is missing in a CA certificate.')
                    result = False
                return result  # End-entity certificates may omit the extension

            # Validate that the Key Usage extension is marked as critical
            if not key_usage_ext.critical:
                self.log_warning('Key Usage extension should be marked as critical.')

            # Extract the key usage values
            key_usage = key_usage_ext.value

            # Ensure at least one bit is set
            if not (
                key_usage.digital_signature
                or key_usage.non_repudiation
                or key_usage.key_encipherment
                or key_usage.data_encipherment
                or key_usage.key_agreement
                or key_usage.key_cert_sign
                or key_usage.crl_sign
                or key_usage.encipher_only
                or key_usage.decipher_only
            ):
                self.log_error('Key Usage extension must have at least one bit set.')
                result = False

            # Specific validations for CA certificates
            if self.is_ca:
                if not key_usage.key_cert_sign:
                    self.log_error('CA certificate must have the keyCertSign bit set in the Key Usage extension.')
                    result = False
                if key_usage.digital_signature or key_usage.non_repudiation:
                    self.log_warning('CA certificates should not have the digitalSignature or nonRepudiation bits set.')
            # Specific validations for key agreement usage
            if key_usage.key_agreement:
                if not key_usage.encipher_only or not key_usage.decipher_only:
                    self.log_error('The encipherOnly and decipherOnly bits are undefined without the keyAgreement bit.')
                    result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Key Usage validation: {e}')
            print(str(e))
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

    def __init__(self, is_ca: bool = None, require_extension: bool = False):
        """Initialize the CertificatePoliciesValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            require_extension (bool): Indicates whether the Certificate Policies extension is required.
        """
        super().__init__()
        self.is_ca = is_ca
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

        try:
            # Attempt to get the Certificate Policies extension
            try:
                cert_policies_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            except Exception:
                cert_policies_ext = None

            if cert_policies_ext is None:
                if self.require_extension:
                    self.log_error('Certificate Policies extension is required but missing.')
                    result = False
                else:
                    self.log_warning('Certificate Policies extension is missing. Its presence depends on usage.')
                return result

            # Validate that the extension is not critical (optional recommendation in RFC 5280)
            if cert_policies_ext.critical:
                self.log_warning('Certificate Policies extension is marked as critical.')

            # Extract the policy information
            cert_policies = cert_policies_ext.value

            # Check for duplicate policy identifiers
            seen_oids = set()
            for policy in cert_policies:
                if policy.policy_identifier in seen_oids:
                    self.log_error(f'Duplicate policy identifier found: {policy.policy_identifier}.')
                    result = False
                seen_oids.add(policy.policy_identifier)

                # Validate policy qualifiers (if present)
                if policy.policy_qualifiers:
                    for qualifier in policy.policy_qualifiers:
                        if hasattr(qualifier, 'explicit_text'):
                            result = self._validate_explicit_text(qualifier.explicit_text) and result

        except Exception as e:
            self.log_error(f'Unexpected error during Certificate Policies validation: {e}')
            result = False

        return result

    def _validate_explicit_text(self, explicit_text) -> bool:
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
        if len(explicit_text) > 200:
            self.log_warning(
                f'explicitText exceeds 200 characters: {len(explicit_text)} characters. '
                'Non-conforming CAs may use larger text.'
            )

        # Check for forbidden encodings
        if isinstance(explicit_text, str):
            return True  # UTF8String or IA5String in modern libraries
        self.log_error('explicitText encoding must be UTF8String or IA5String.')
        return False


class PolicyMappingsValidation(Validation):
    """Validates the Policy Mappings extension of a certificate (RFC 5280, Section 4.2.1.5).

    This validation ensures:
    - The Policy Mappings extension is present only in CA certificates.
    - Policies are not mapped to or from the special value anyPolicy.
    - Each issuerDomainPolicy in the Policy Mappings extension is asserted in the Certificate Policies extension.
    """

    def __init__(self, is_ca: bool = None, require_extension: bool = False):
        """Initialize the PolicyMappingsValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            require_extension (bool): Indicates whether the Policy Mappings extension is required.
        """
        super().__init__()
        self.is_ca = is_ca
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Policy Mappings extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Policy Mappings extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Policy Mappings extension
            try:
                policy_mappings_ext = cert.extensions.get_extension_for_oid(ExtensionOID.POLICY_MAPPINGS)
            except Exception:
                policy_mappings_ext = None

            if policy_mappings_ext is None:
                if self.require_extension:
                    self.log_error('Policy Mappings extension is required but missing.')
                    result = False
                elif self.is_ca:
                    self.log_warning('Policy Mappings extension is missing in a CA certificate.')
                return result

            # Ensure the extension is marked as critical
            if not policy_mappings_ext.critical:
                self.log_warning('Policy Mappings extension should be marked as critical.')

            # Extract the Policy Mappings
            policy_mappings = policy_mappings_ext.value

            # Validate each mapping
            for mapping in policy_mappings:
                issuer_policy = mapping.issuer_domain_policy
                subject_policy = mapping.subject_domain_policy

                # Check for anyPolicy usage
                if issuer_policy.dotted_string == '2.5.29.32.0' or subject_policy.dotted_string == '2.5.29.32.0':
                    self.log_error('Policies must not be mapped to or from anyPolicy.')
                    result = False

                # Check if issuerDomainPolicy is included in Certificate Policies
                if not self._is_policy_in_certificate_policies(cert, issuer_policy):
                    self.log_error(
                        f'issuerDomainPolicy {issuer_policy} is not asserted in the Certificate Policies extension.'
                    )
                    result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Policy Mappings validation: {e}')
            result = False

        return result

    def _is_policy_in_certificate_policies(self, cert: Certificate, policy_oid) -> bool:
        """Check if a policy OID is present in the Certificate Policies extension.

        Args:
            cert (Certificate): The certificate to check.
            policy_oid: The OID of the policy to look for.

        Returns:
            bool: True if the policy is present, False otherwise.
        """
        try:
            cert_policies_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            cert_policies = cert_policies_ext.value
            for policy in cert_policies:
                if policy.policy_identifier == policy_oid:
                    return True
        except Exception:
            pass

        return False


class SubjectAlternativeNameValidation(Validation):
    """Validates the Subject Alternative Name (SAN) extension of a certificate (RFC 5280, Section 4.2.1.6).

    This validation ensures:
    - The SAN extension is present when required.
    - The SAN extension contains at least one valid entry.
    - Entries conform to encoding and syntax rules (e.g., rfc822Name, dNSName, iPAddress, URI).
    """

    def __init__(self, require_extension: bool = False):
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
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            except Exception:
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
                result = False
                return result

            # Validate individual SAN entries
            for name in san:
                result = self._validate_san_entry(name) and result

        except Exception as e:
            self.log_error(f'Unexpected error during SAN validation: {e}')
            result = False

        return result

    def _validate_san_entry(self, name) -> bool:
        """Validate an individual SAN entry.

        Args:
            name: The SAN entry to validate.

        Returns:
            bool: True if the SAN entry is valid, False otherwise.

        Logs:
            Errors for invalid SAN entries.
        """
        try:
            if isinstance(name, RFC822Name):
                return self._validate_rfc822name(name.value)
            if isinstance(name, DNSName):
                return self._validate_dnsname(name.value)
            if isinstance(name, UniformResourceIdentifier):
                return self._validate_uri(name.value)
            if isinstance(name, IPAddress):
                return self._validate_ipaddress(name.value)
            if isinstance(name, RegisteredID):
                self.log_warning(
                    f'RegisteredID SAN entry is present: {name.value}. Ensure it is correctly interpreted.'
                )
                return True
            if isinstance(name, DirectoryName):
                self.log_warning('DirectoryName SAN entry is present. Ensure it complies with encoding rules.')
                return True
            if isinstance(name, OtherName):
                self.log_warning(f'OtherName SAN entry is present with type-id {name.type_id}.')
                return True
            self.log_error(f'Unsupported SAN entry type: {type(name).__name__}')
            return False

        except Exception as e:
            self.log_error(f'Error validating SAN entry: {e}')
            return False

    def _validate_rfc822name(self, value: str) -> bool:
        """Validate an rfc822Name (email address) SAN entry.

        Args:
            value (str): The rfc822Name to validate.

        Returns:
            bool: True if the rfc822Name is valid, False otherwise.
        """
        if '@' not in value:
            self.log_error(f'Invalid rfc822Name: {value}')
            return False
        return True

    def _validate_dnsname(self, value: str) -> bool:
        """Validate a dNSName SAN entry.

        Args:
            value (str): The dNSName to validate.

        Returns:
            bool: True if the dNSName is valid, False otherwise.
        """
        if value.strip() == '' or value == ' ':
            self.log_error('dNSName cannot be empty or a single space.')
            return False
        return True

    def _validate_ipaddress(self, value) -> bool:
        """Validate an iPAddress SAN entry.

        Args:
            value: The iPAddress to validate.

        Returns:
            bool: True if the iPAddress is valid, False otherwise.

        Logs:
            Warnings if the iPAddress is a network address (e.g., 192.168.127.0/24).
        """
        try:
            # Attempt to parse as an individual IP address
            ip = ip_address(value)
            return True
        except ValueError:
            try:
                # Check if it's a network range (subnet)
                network = ip_network(value, strict=True)
                self.log_warning(
                    f'iPAddress contains a network address: {network}. Networks are not standard for SANs.'
                )
                return False
            except ValueError:
                self.log_error(f'Invalid iPAddress: {value}')
                return False

    def _validate_uri(self, value: str) -> bool:
        """Validate a URI SAN entry.

        Args:
            value (str): The URI to validate.

        Returns:
            bool: True if the URI is valid, False otherwise.
        """
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            self.log_error(f'Invalid URI: {value}')
            return False
        return True


class IssuerAlternativeNameValidation(Validation):
    """Validates the Issuer Alternative Name (IAN) extension of a certificate (RFC 5280, Section 4.2.1.7).

    This validation ensures:
    - The IAN extension is encoded as specified in Section 4.2.1.6.
    - Entries conform to encoding and syntax rules (e.g., rfc822Name, dNSName, iPAddress, URI).
    - Where present, the IAN extension is marked as non-critical.
    """

    def __init__(self, require_extension: bool = False):
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
                ian_ext = cert.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
            except Exception:
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
                result = False
                return result

            # Validate individual IAN entries
            for name in ian:
                result = self._validate_ian_entry(name) and result

        except Exception as e:
            self.log_error(f'Unexpected error during IAN validation: {e}')
            result = False

        return result

    def _validate_ian_entry(self, name) -> bool:
        """Validate an individual IAN entry.

        Args:
            name: The IAN entry to validate.

        Returns:
            bool: True if the IAN entry is valid, False otherwise.

        Logs:
            Errors for invalid IAN entries.
        """
        try:
            if isinstance(name, RFC822Name):
                return self._validate_rfc822name(name.value)
            if isinstance(name, DNSName):
                return self._validate_dnsname(name.value)
            if isinstance(name, UniformResourceIdentifier):
                return self._validate_uri(name.value)
            if isinstance(name, IPAddress):
                return self._validate_ipaddress(name.value)
            if isinstance(name, RegisteredID):
                self.log_warning(
                    f'RegisteredID IAN entry is present: {name.value}. Ensure it is correctly interpreted.'
                )
                return True
            if isinstance(name, DirectoryName):
                self.log_warning('DirectoryName IAN entry is present. Ensure it complies with encoding rules.')
                return True
            if isinstance(name, OtherName):
                self.log_warning(f'OtherName IAN entry is present with type-id {name.type_id}.')
                return True
            self.log_error(f'Unsupported IAN entry type: {type(name).__name__}')
            return False

        except Exception as e:
            self.log_error(f'Error validating IAN entry: {e}')
            return False

    def _validate_rfc822name(self, value: str) -> bool:
        """Validate an rfc822Name (email address) IAN entry.

        Args:
            value (str): The rfc822Name to validate.

        Returns:
            bool: True if the rfc822Name is valid, False otherwise.
        """
        if '@' not in value:
            self.log_error(f'Invalid rfc822Name: {value}')
            return False
        return True

    def _validate_dnsname(self, value: str) -> bool:
        """Validate a dNSName IAN entry.

        Args:
            value (str): The dNSName to validate.

        Returns:
            bool: True if the dNSName is valid, False otherwise.
        """
        if value.strip() == '' or value == ' ':
            self.log_error('dNSName cannot be empty or a single space.')
            return False
        return True

    def _validate_ipaddress(self, value) -> bool:
        """Validate an iPAddress IAN entry.

        Args:
            value: The iPAddress to validate.

        Returns:
            bool: True if the iPAddress is valid, False otherwise.
        """
        try:
            # Attempt to parse as an individual IP address
            ip = ip_address(value)
            return True
        except ValueError:
            try:
                # Check if it's a network range (subnet)
                network = ip_network(value, strict=True)
                self.log_warning(
                    f'iPAddress contains a network address: {network}. Networks are not standard for SANs.'
                )
                return False
            except ValueError:
                self.log_error(f'Invalid iPAddress: {value}')
                return False

    def _validate_uri(self, value: str) -> bool:
        """Validate a URI IAN entry.

        Args:
            value (str): The URI to validate.

        Returns:
            bool: True if the URI is valid, False otherwise.
        """
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            self.log_error(f'Invalid URI: {value}')
            return False
        return True


class SubjectDirectoryAttributesValidation(Validation):
    """Validates the Subject Directory Attributes extension of a certificate (RFC 5280, Section 4.2.1.8).

    This validation ensures:
    - The extension is marked as non-critical.
    - The extension contains one or more attributes if present.
    """

    def __init__(self, require_extension: bool = False):
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
            except Exception:
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

        except Exception as e:
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

    def __init__(self, is_ca: bool = None, require_extension: bool = False):
        """Initialize the BasicConstraintsValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            require_extension (bool): Indicates whether the Basic Constraints extension is required.
        """
        super().__init__()
        self.is_ca = is_ca
        self.require_extension = require_extension

    def validate(self, cert: Certificate) -> bool:
        """Validate the Basic Constraints extension of the given certificate.

        Args:
            cert (Certificate): The X.509 certificate to validate.

        Returns:
            bool: True if the validation passes, False otherwise.

        Logs:
            Errors for missing or incorrectly configured Basic Constraints extensions.
            Warnings for optional fields and best practices.
        """
        result = True

        try:
            # Attempt to get the Basic Constraints extension
            try:
                basic_constraints_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            except Exception:
                basic_constraints_ext = None

            if basic_constraints_ext is None:
                if self.require_extension:
                    self.log_error('Basic Constraints extension is required but missing.')
                    result = False
                return result

            # Validate criticality for CA certificates
            if self.is_ca and not basic_constraints_ext.critical:
                self.log_error('Basic Constraints extension must be marked as critical in CA certificates.')
                result = False

            # Extract Basic Constraints values
            basic_constraints = basic_constraints_ext.value
            cA = basic_constraints.ca
            path_len = basic_constraints.path_length

            # Validate cA boolean
            if self.is_ca and not cA:
                self.log_error('CA certificate must assert the cA boolean in the Basic Constraints extension.')
                result = False
            elif not self.is_ca and cA:
                self.log_error(
                    'End-entity certificate must not assert the cA boolean in the Basic Constraints extension.'
                )
                result = False

            # Validate pathLenConstraint
            if path_len is not None:
                if not cA:
                    self.log_error('pathLenConstraint must not be present unless the cA boolean is asserted.')
                    result = False
                elif path_len < 0:
                    self.log_error('pathLenConstraint must be greater than or equal to zero.')
                    result = False

            # Cross-validation with Key Usage
            try:
                key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                key_usage = key_usage_ext.value
                if cA and key_usage.key_cert_sign is False:
                    self.log_error(
                        'CA certificate with cA boolean asserted must also assert the keyCertSign bit in Key Usage.'
                    )
                    result = False
            except Exception:
                if cA:
                    self.log_warning('Key Usage extension is missing. Cannot validate keyCertSign bit.')

        except Exception as e:
            self.log_error(f'Unexpected error during Basic Constraints validation: {e}')
            result = False

        return result


class NameConstraintsValidation(Validation):
    """Validates the Name Constraints extension of a certificate (RFC 5280, Section 4.2.1.10).

    This validation ensures:
    - The Name Constraints extension is present only in CA certificates.
    - The extension is marked as critical.
    - Either permittedSubtrees or excludedSubtrees are present (not an empty sequence).
    - Each name constraint complies with the specified syntax and semantics.
    """

    def __init__(self, is_ca: bool = True, require_extension: bool = False):
        """Initialize the NameConstraintsValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            require_extension (bool): Indicates whether the Name Constraints extension is required.
        """
        super().__init__()
        self.is_ca = is_ca
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
            except Exception:
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
            name_constraints = name_constraints_ext.value
            permitted_subtrees = name_constraints.permitted_subtrees
            excluded_subtrees = name_constraints.excluded_subtrees

            # Validate that either permitted or excluded subtrees are present
            if not permitted_subtrees and not excluded_subtrees:
                self.log_error(
                    'Name Constraints extension must contain at least one of permittedSubtrees or excludedSubtrees.'
                )
                result = False

            # Validate individual constraints
            if permitted_subtrees:
                result = self._validate_subtrees(permitted_subtrees, 'permittedSubtrees') and result
            if excluded_subtrees:
                result = self._validate_subtrees(excluded_subtrees, 'excludedSubtrees') and result

        except Exception as e:
            self.log_error(f'Unexpected error during Name Constraints validation: {e}')
            result = False

        return result

    def _validate_subtrees(self, subtrees, subtree_type: str) -> bool:
        """Validate the subtrees (permitted or excluded).

        Args:
            subtrees: The subtrees to validate.
            subtree_type (str): Either "permittedSubtrees" or "excludedSubtrees".

        Returns:
            bool: True if the subtrees are valid, False otherwise.
        """
        result = True

        for subtree in subtrees:
            base = subtree.base
            if isinstance(base, RFC822Name):
                result = self._validate_rfc822name(base.value, subtree_type) and result
            elif isinstance(base, DNSName):
                result = self._validate_dnsname(base.value, subtree_type) and result
            elif isinstance(base, UniformResourceIdentifier):
                result = self._validate_uri(base.value, subtree_type) and result
            elif isinstance(base, IPAddress):
                result = self._validate_ipaddress(base.value, subtree_type) and result
            else:
                self.log_warning(f'Unsupported GeneralName type in {subtree_type}: {type(base).__name__}.')
        return result

    def _validate_rfc822name(self, value: str, subtree_type: str) -> bool:
        """Validate an rfc822Name constraint.

        Args:
            value (str): The rfc822Name to validate.
            subtree_type (str): Either "permittedSubtrees" or "excludedSubtrees".

        Returns:
            bool: True if the rfc822Name is valid, False otherwise.
        """
        if '@' in value or value.startswith('.'):
            return True
        self.log_error(f'Invalid rfc822Name in {subtree_type}: {value}. Must specify a mailbox, host, or domain.')
        return False

    def _validate_dnsname(self, value: str, subtree_type: str) -> bool:
        """Validate a dNSName constraint.

        Args:
            value (str): The dNSName to validate.
            subtree_type (str): Either "permittedSubtrees" or "excludedSubtrees".

        Returns:
            bool: True if the dNSName is valid, False otherwise.
        """
        if value.startswith('.') or value.strip() != '':
            return True
        self.log_error(f'Invalid dNSName in {subtree_type}: {value}.')
        return False

    def _validate_uri(self, value: str, subtree_type: str) -> bool:
        """Validate a URI constraint.

        Args:
            value (str): The URI to validate.
            subtree_type (str): Either "permittedSubtrees" or "excludedSubtrees".

        Returns:
            bool: True if the URI is valid, False otherwise.
        """
        if value.startswith('http://') or value.startswith('https://'):
            return True
        self.log_error(f'Invalid URI in {subtree_type}: {value}. Must specify a host or domain.')
        return False

    def _validate_ipaddress(self, value: bytes, subtree_type: str) -> bool:
        """Validate an IPAddress constraint.

        Args:
            value (bytes): The IPAddress to validate.
            subtree_type (str): Either "permittedSubtrees" or "excludedSubtrees".

        Returns:
            bool: True if the IPAddress is valid, False otherwise.
        """
        try:
            ip_network(value.decode('utf-8'), strict=False)
            return True
        except ValueError:
            self.log_error(f'Invalid IPAddress in {subtree_type}: {value}. Must be a valid subnet.')
            return False


class PolicyConstraintsValidation(Validation):
    """Validates the Policy Constraints extension of a certificate (RFC 5280, Section 4.2.1.11).

    This validation ensures:
    - The Policy Constraints extension is present only in CA certificates.
    - The extension is marked as critical.
    - Either the requireExplicitPolicy or inhibitPolicyMapping field is present (not an empty sequence).
    - The values of requireExplicitPolicy and inhibitPolicyMapping are non-negative integers.
    """

    def __init__(self, is_ca: bool = True, require_extension: bool = False):
        """Initialize the PolicyConstraintsValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            require_extension (bool): Indicates whether the Policy Constraints extension is required.
        """
        super().__init__()
        self.is_ca = is_ca
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
                policy_constraints_ext = cert.extensions.get_extension_for_oid(ExtensionOID.POLICY_CONSTRAINTS)
            except Exception:
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
                    'Policy Constraints extension must contain at least one of requireExplicitPolicy or inhibitPolicyMapping.'
                )
                result = False

            # Validate requireExplicitPolicy
            if require_explicit_policy is not None:
                if require_explicit_policy < 0:
                    self.log_error('requireExplicitPolicy must be a non-negative integer.')
                    result = False

            # Validate inhibitPolicyMapping
            if inhibit_policy_mapping is not None:
                if inhibit_policy_mapping < 0:
                    self.log_error('inhibitPolicyMapping must be a non-negative integer.')
                    result = False

        except Exception as e:
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

    def __init__(self, is_ca: bool = False, required_purposes: list = None):
        """Initialize the ExtendedKeyUsageValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
            required_purposes (list): A list of OIDs (as strings) indicating the expected key purposes.
        """
        super().__init__()
        self.is_ca = is_ca
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
                eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            except Exception:
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
                self.log_info('anyExtendedKeyUsage is present. No restrictions on key purposes.')

            # Validate required purposes
            if self.required_purposes:
                for purpose in self.required_purposes:
                    if purpose not in eku_values:
                        self.log_error(f'Required key purpose {purpose} is missing from EKU.')
                        result = False

            # Cross-validation with Key Usage
            result = self._validate_consistency_with_key_usage(cert, eku_values) and result

        except Exception as e:
            self.log_error(f'Unexpected error during Extended Key Usage validation: {e}')
            result = False

        return result

    def _validate_consistency_with_key_usage(self, cert: Certificate, eku_values) -> bool:
        """Validate consistency between the EKU and Key Usage extensions.

        Args:
            cert (Certificate): The X.509 certificate.
            eku_values: The values of the EKU extension.

        Returns:
            bool: True if the EKU and Key Usage extensions are consistent, False otherwise.
        """
        result = True

        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usage = key_usage_ext.value

            for eku in eku_values:
                if eku == ExtendedKeyUsageOID.SERVER_AUTH:
                    if not (key_usage.digital_signature or key_usage.key_encipherment or key_usage.key_agreement):
                        self.log_error('Key Usage is inconsistent with serverAuth in EKU.')
                        result = False
                elif eku == ExtendedKeyUsageOID.CLIENT_AUTH:
                    if not (key_usage.digital_signature or key_usage.key_agreement):
                        self.log_error('Key Usage is inconsistent with clientAuth in EKU.')
                        result = False
                elif eku == ExtendedKeyUsageOID.CODE_SIGNING:
                    if not key_usage.digital_signature:
                        self.log_error('Key Usage is inconsistent with codeSigning in EKU.')
                        result = False
                elif eku == ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    if not (
                        key_usage.digital_signature
                        or key_usage.non_repudiation
                        or key_usage.key_encipherment
                        or key_usage.key_agreement
                    ):
                        self.log_error('Key Usage is inconsistent with emailProtection in EKU.')
                        result = False
                elif eku == ExtendedKeyUsageOID.TIME_STAMPING:
                    if not (key_usage.digital_signature or key_usage.non_repudiation):
                        self.log_error('Key Usage is inconsistent with timeStamping in EKU.')
                        result = False
                elif eku == ExtendedKeyUsageOID.OCSP_SIGNING:
                    if not (key_usage.digital_signature or key_usage.non_repudiation):
                        self.log_error('Key Usage is inconsistent with OCSPSigning in EKU.')
                        result = False

        except Exception:
            self.log_warning('Key Usage extension is missing. Cannot validate consistency with EKU.')

        return result


class CRLDistributionPointsValidation(Validation):
    """Validates the CRL Distribution Points extension of an X.509 certificate (RFC 5280, Section 4.2.1.13).

    This validation ensures:
    - The CRL Distribution Points extension is present and contains at least one DistributionPoint.
    - The DistributionPoint should contain either a distributionPoint or cRLIssuer field, or both.
    - The CRL Distribution Points extension should be non-critical, as recommended by RFC 5280.
    - The extension includes valid URI or directory name for CRL retrieval.
    """

    def __init__(self, is_ca: bool = False):
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
            # Attempt to get the CRL Distribution Points extension
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            except Exception:
                crl_ext = None

            if crl_ext is None:
                self.log_warning(
                    "CRL Distribution Points extension is missing. It's recommended for CAs and applications to support it."
                )
                return result

            # Extract the CRL Distribution Points value
            crl_values = crl_ext.value

            # Ensure at least one DistributionPoint is present
            if not crl_values:
                self.log_error(
                    'CRL Distribution Points extension is empty. At least one DistributionPoint is required.'
                )
                result = False

            # Validate each DistributionPoint
            for dp in crl_values:
                if not dp.distribution_point and not dp.cRLIssuer:
                    self.log_error('A DistributionPoint must contain either a distributionPoint or cRLIssuer field.')
                    result = False

                if dp.cRLIssuer and not dp.cRLIssuer[0].value:
                    self.log_error('cRLIssuer field is present but does not contain a valid distinguished name.')
                    result = False

                # If distributionPoint is present, check for valid URIs or names
                if dp.distribution_point:
                    for name in dp.distribution_point:
                        if name.choice == UniformResourceIdentifier:
                            uri = name.value
                            if not self._is_valid_uri(uri):
                                self.log_error(f'Invalid URI in distributionPoint: {uri}')
                                result = False

            # Ensure the CRL Distribution Points extension is non-critical, as recommended
            if crl_ext.critical:
                self.log_warning('CRL Distribution Points extension should be non-critical as recommended by RFC 5280.')
                result = False

        except Exception as e:
            self.log_error(f'Unexpected error during CRL Distribution Points validation: {e}')
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
    - The SkipCerts value indicates the number of non-self-issued certificates that may appear before anyPolicy is no longer permitted.
    """

    def __init__(self, is_ca: bool = False):
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
                inhibit_any_policy_ext = cert.extensions.get_extension_for_oid(ExtensionOID.INHIBIT_ANY_POLICY)
            except Exception:
                inhibit_any_policy_ext = None

            if inhibit_any_policy_ext is None:
                if self.is_ca:
                    self.log_error(
                        'Inhibit Any Policy extension is missing in a CA certificate. It is mandatory for CA certificates.'
                    )
                    result = False
                return result

            # Extract the value (SkipCerts)
            skip_certs = inhibit_any_policy_ext.value

            # Ensure the extension is critical, as required by RFC 5280
            if not inhibit_any_policy_ext.critical:
                self.log_error('Inhibit Any Policy extension must be marked as critical, as required by RFC 5280.')
                result = False

            # Validate the SkipCerts value (must be within the valid range)
            if not (0 <= skip_certs <= 255):  # Based on the INTEGER specification (0..MAX), MAX here is typically 255
                self.log_error(
                    f'Inhibit Any Policy extension contains an invalid SkipCerts value: {skip_certs}. It must be between 0 and 255.'
                )
                result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Inhibit Any Policy validation: {e}')
            result = False

        return result


class FreshestCRLValidation(Validation):
    """Validates the Freshest CRL (Delta CRL Distribution Point) extension of an X.509 certificate (RFC 5280, Section 4.2.1.15).

    This validation ensures:
    - The Freshest CRL extension is present.
    - The extension is marked as non-critical, as required by RFC 5280.
    - The extension contains valid CRL distribution points for delta CRLs, following the same structure as the cRLDistributionPoints extension.
    """

    def __init__(self, is_ca: bool = False):
        """Initialize the FreshestCRLValidation.

        Args:
            is_ca (bool): True if the certificate is a CA certificate, False otherwise.
                          This parameter is included for consistency, though it's not directly relevant to Freshest CRL validation.
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
            # Attempt to get the Freshest CRL extension
            try:
                freshest_crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL)
            except Exception:
                freshest_crl_ext = None

            if freshest_crl_ext is None:
                self.log_warning('Freshest CRL extension is missing. Conforming CAs are encouraged to include it.')
                return result

            # Extract the CRL Distribution Points from the Freshest CRL extension
            crl_values = freshest_crl_ext.value

            # Ensure the extension is non-critical, as required by RFC 5280
            if freshest_crl_ext.critical:
                self.log_error('Freshest CRL extension must be marked as non-critical, as required by RFC 5280.')
                result = False

            # Validate the CRL Distribution Points (same structure as cRLDistributionPoints)
            for dp in crl_values:
                if not dp.distribution_point and not dp.cRLIssuer:
                    self.log_error(
                        'A DistributionPoint in the Freshest CRL extension must contain either a distributionPoint or cRLIssuer field.'
                    )
                    result = False

                if dp.cRLIssuer and not dp.cRLIssuer[0].value:
                    self.log_error(
                        'cRLIssuer field is present in Freshest CRL extension but does not contain a valid distinguished name.'
                    )
                    result = False

                # Check for valid URI in distributionPoint
                if dp.distribution_point:
                    for name in dp.distribution_point:
                        if name.choice == UniformResourceIdentifier:
                            uri = name.value
                            if not self._is_valid_uri(uri):
                                self.log_error(f'Invalid URI in distributionPoint of Freshest CRL extension: {uri}')
                                result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Freshest CRL validation: {e}')
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


###########


class SubjectAttributesValidation(Validation):
    """Validates the subject attributes of an X.509 certificate using OIDs.

    This validation ensures:
    - Certain subject attributes, identified by OID, must exist and match one of the specified exact values or regex patterns.
    - Optional subject attributes, identified by OID, must match at least one regex pattern if present.
    - If any attribute exists that is not required or optional, validation fails.
    """

    def __init__(self, required: dict = None, optional: dict = None):
        """Initialize the SubjectAttributesValidation.

        Args:
            required (dict): A dictionary where the key is the OID of the attribute
                             and the value is either a single exact value, a list of exact values,
                             a regex pattern, or a list of regex patterns.
            optional (dict): A dictionary where the key is the OID of the attribute
                             and the value is a regex pattern or a list of regex patterns.
        """
        super().__init__()
        self.required = required or {}
        self.optional = optional or {}

    def validate(self, cert: Certificate, strict=True) -> bool:
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
            # Convert the subject to a dictionary with OIDs as keys and lists of values
            subject_dict = self._convert_subject_to_dict(cert.subject)

            print(subject_dict)

            # Keep track of unmatched patterns and values
            unmatched_patterns = {}
            unmatched_values = {}

            # Match values from the subject against required patterns
            for oid, required_patterns in self.required.items():
                attr_values = subject_dict.get(oid, [])
                unmatched_patterns[oid] = set(required_patterns)
                unmatched_values[oid] = set(attr_values)

                for value in list(unmatched_values[oid]):
                    for pattern in list(unmatched_patterns[oid]):
                        if self._match_value_or_regex(value, pattern):
                            unmatched_patterns[oid].discard(pattern)
                            unmatched_values[oid].discard(value)
                            break  # Move to the next value once matched

            # Match remaining values against optional patterns
            for oid, optional_patterns in self.optional.items():
                attr_values = subject_dict.get(oid, [])
                if oid not in unmatched_values:
                    unmatched_values[oid] = set(attr_values)
                optional_matches = set()

                for value in list(unmatched_values[oid]):
                    if any(self._match_value_or_regex(value, pattern) for pattern in optional_patterns):
                        optional_matches.add(value)

                # Remove matched optional values
                unmatched_values[oid] -= optional_matches

            # Handle attributes with no patterns
            for oid, attr_values in subject_dict.items():
                if oid not in self.required and oid not in self.optional:
                    if strict:
                        self.log_error(f'Unexpected attribute with OID {oid} and values {attr_values}.')
                        result = False

            # Report errors for unmatched required patterns
            for oid, patterns in unmatched_patterns.items():
                if patterns:
                    self.log_error(f'Required attribute with OID {oid} is missing patterns: {list(patterns)}.')
                    result = False

            # Report errors for unmatched values
            for oid, values in unmatched_values.items():
                if values:
                    self.log_error(f'Attribute with OID {oid} has unmatched values: {list(values)}.')
                    result = False

        except Exception as e:
            self.log_error(f'Unexpected error during Subject Attributes validation: {e}')
            result = False

        return result

    def _convert_subject_to_dict(self, subject):
        """Converts the subject field to a dictionary with OIDs as keys and lists of attribute values.

        Args:
            subject: The subject field of the certificate.

        Returns:
            A dictionary where the keys are OIDs (str) and the values are lists of attribute values (str).
        """
        subject_dict = {}
        for relative_distinguished_name in subject:
            oid = relative_distinguished_name.oid.dotted_string
            value = relative_distinguished_name.value
            if oid not in subject_dict:
                subject_dict[oid] = []
            subject_dict[oid].append(value)
        return subject_dict

    def _match_value_or_regex(self, attr_value, pattern):
        """Matches the attribute value against one or more exact values or regex patterns.

        Args:
            attr_value: The value of the attribute from the certificate.
            patterns: A single exact value, regex pattern, or a list of such values or patterns.

        Returns:
            bool: True if it matches any value or pattern, False otherwise.
        """
        if isinstance(pattern, str):
            # Exact match
            return attr_value == pattern
        if isinstance(pattern, re.Pattern):
            # Regex match
            return pattern.match(attr_value) is not None
        return False


##########


class SANAttributesValidation(Validation):
    """Validates the Subject Alternative Names (SAN) of an X.509 certificate using OIDs.

    This validation ensures:
    - Certain SANs, identified by OID, must exist and match one of the specified exact values or regex patterns.
    - Optional SANs, identified by OID, must match at least one regex pattern if present.
    - If any SAN exists that is not required or optional, validation fails.
    """

    def __init__(self, required: dict = None, optional: dict = None):
        """Initialize the SANAttributesValidation.

        Args:
            required (dict): A dictionary where the key is the OID of the SAN attribute
                             and the value is either a single exact value, a list of exact values,
                             a regex pattern, or a list of regex patterns.
            optional (dict): A dictionary where the key is the OID of the SAN attribute
                             and the value is a regex pattern or a list of regex patterns.
        """
        super().__init__()
        self.required = required or {}
        self.optional = optional or {}

    def validate(self, cert: Certificate, strict=True) -> bool:
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
            try:
                san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = san_extension.value
            except ExtensionNotFound:
                self.log_error('The certificate does not contain a Subject Alternative Name (SAN) extension.')
                return False

            # Convert SAN list to a dictionary with OIDs as keys
            san_dict = self._convert_san_to_dict(san_list)

            # Track unmatched patterns and values
            unmatched_patterns = {}
            unmatched_values = {}

            # Validate required SAN attributes
            for oid, required_patterns in self.required.items():
                san_values = san_dict.get(oid, [])
                unmatched_patterns[oid] = set(required_patterns)
                unmatched_values[oid] = set(san_values)

                for value in list(unmatched_values[oid]):
                    for pattern in list(unmatched_patterns[oid]):
                        if self._match_value_or_regex(value, pattern):
                            unmatched_patterns[oid].discard(pattern)
                            unmatched_values[oid].discard(value)
                            break

            # Validate optional SAN attributes
            for oid, optional_patterns in self.optional.items():
                san_values = san_dict.get(oid, [])
                if oid not in unmatched_values:
                    unmatched_values[oid] = set(san_values)
                optional_matches = set()

                for value in list(unmatched_values[oid]):
                    if any(self._match_value_or_regex(value, pattern) for pattern in optional_patterns):
                        optional_matches.add(value)

                # Remove matched optional values
                unmatched_values[oid] -= optional_matches

            # Handle unexpected SAN attributes
            for oid, san_values in san_dict.items():
                if oid not in self.required and oid not in self.optional:
                    if strict:
                        self.log_error(f'Unexpected SAN attribute {oid} and values {san_values}.')
                        result = False

            # Report errors for unmatched required patterns
            for oid, patterns in unmatched_patterns.items():
                if patterns:
                    self.log_error(f'Required SAN attribute {oid} is missing patterns: {list(patterns)}.')
                    result = False

            # Report errors for unmatched values
            for oid, values in unmatched_values.items():
                if values:
                    self.log_error(f'SAN attribute {oid} has unmatched values: {list(values)}.')
                    result = False

        except Exception as e:
            self.log_error(f'Unexpected error during SAN validation: {e}')
            result = False

        return result

    def _convert_san_to_dict(self, san_list):
        """Converts the SAN list to a dictionary using GeneralName naming conventions.

        Args:
            san_list: The SAN extension value, typically a sequence of GeneralNames.

        Returns:
            A dictionary where keys are GeneralName types (e.g., 'dNSName', 'IPAddress')
            and values are lists of attribute values.
        """
        san_dict = {
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
                raise ValueError(f'Unknown SAN type encountered: {san.__class__.__name__}')

        # Remove keys with empty lists
        san_dict = {key: value for key, value in san_dict.items() if value}

        return san_dict

    def _match_value_or_regex(self, attr_value, pattern):
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
