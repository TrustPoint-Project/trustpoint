from enum import Enum

from cryptography import x509
from django.utils.translation import gettext_lazy as _

SERIAL_MAX_VALUE = 1_461_501_637_330_902_918_203_684_832_716_283_019_655_932_542_975


class ErrorSource(Enum):
    BSI = _('BSI Technical Guideline TR-02103')
    RFC5280 = _('RFC5280')
    TRUSTPOINT = _('Trustpoint specified constraint.')


class CertificateError(Enum):
    # error msg, code, source
    INVALID_VERSION = (_('Certificate version is not v3.'), 'invalid_version', ErrorSource.TRUSTPOINT)
    SERIAL_NUMBER_0 = (_('Certificate serial number is 0.'), 'serial_number_0', ErrorSource.RFC5280)
    SERIAL_NUMBER_NEGATIVE = (
        _('Certificate serial number is negative.'),
        'serial_number_negative',
        ErrorSource.RFC5280,
    )
    SHORT_SERIAL_NUMBER = (_('Certificate serial number is shorter than 20 bytes.'), 'short_serial_number')
    EXT_ISSUER_ALTERNATIVE_NAME_CRITICAL = (
        _('The Issuer Alternative Name extension of the CA certificate is marked as critical.'),
        'ext_key_usage_non_critical',
    )
    EXT_KEY_USAGE_MISSING = (_('CA certificate does not contain the Key Usage extension.'), 'ext_key_usage_missing')
    EXT_KEY_USAGE_NON_CRITICAL = (
        _('The Key Usage extension of the CA certificate is marked as non-critical.'),
        'ext_key_usage_non_critical',
    )
    EXT_POLICY_MAPPING_NON_CRITICAL = (
        _('The Policy Mappings extension of the CA certificate is marked as non-critical.'),
        'ext_policy_mappings_non_critical',
    )
    EXT_SUBJECT_ALTERNATIVE_NAME_CRITICAL = (
        _(
            'The Subject Alternative Name (SAN) extension of the CA certificate is marked as critical, '
            'while the subject is not emtpy.'
        ),
        'ext_key_usage_non_critical',
    )
    EXT_AUTHORITY_KEY_ID_MISSING = (
        _('Certificate does not contain the Authority Key Identifier extension.'),
        'ext_authority_key_id_missing',
    )
    EXT_AUTHORITY_KEY_ID_CRITICAL = (
        _('The Authority Key Identifier extension is marked as critical.'),
        'authority_key_id_critical',
    )
    EXT_SUBJECT_KEY_ID_CRITICAL = (
        _('The Subject Key Identifier extension is marked as critical.'),
        'subject_key_id_critical',
    )
    EXT_BASIC_CONSTRAINTS_MISSING = (
        _('CA certificate does not have a Basic Constraints extension.'),
        'ext_basic_constraints_missing',
    )
    EXT_BASIC_CONSTRAINTS_NON_CRITICAL = (
        _('The Basic Constraints extension of the CA certificate is marked as non-critical.'),
        'ext_basic_constraints_non_critical',
    )
    EXT_BASIC_CONSTRAINTS_NON_CA = (
        _('CA certificate has a Basic Constraints extension stating that the certificate is not a CA.'),
        'ext_basic_constraints_non_ca',
    )
    EXT_KEY_USAGE_FLAG_MISSING = (
        _(
            'The Key Usage extension of the CA certificate missing '
            'one or more appropriate key usages (keyCertSign, cRLSign, digitalSignature).'
        ),
        'ext_key_usage_flag_missing',
    )
    EXT_SUBJECT_KEY_ID_MISSING = (
        _('Certificate does not contain the Subject Key Identifier extension.'),
        'ext_authority_key_id_missing',
    )
    EXT_POLICY_CONSTRAINTS_NON_CRITICAL = (
        _('The Policy Constraints extension of the CA certificate is marked as non-critical.'),
        'ext_policy_constraints_non_critical',
    )
    EXT_INHIBIT_ANY_POLICY_NON_CRITICAL = (
        _('The Inhibit Any Policy extension of the CA certificate is marked as non-critical.'),
        'ext_policy_mappings_non_critical',
    )
    EXT_SUBJECT_ALTERNATIVE_NAME_NON_CRITICAL = (
        _(
            'The Subject Alternative Name extension of the CA certificate is marked as non-critical, '
            'while the subject is emtpy'
        ),
        'ext_policy_constraints_non_critical',
    )
    EXT_AUTHORITY_KEY_ID_KEY_ID_MISSING = (
        _('The Authority Key Identifier Extension of the CA certificate does not contain the Key Identifier field.'),
        'ext_authority_key_id_missing',
    )


class CertificateValidator:
    _certificate: x509.Certificate
    _was_processed: bool = False
    _is_valid: bool = False
    _errors: list[CertificateError] = []
    _warnings: list[CertificateError] = []

    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate

    def _add_warning(self, warning: CertificateError) -> None:
        self._warnings.append(warning)

    def _add_error(self, error: CertificateError) -> None:
        self._errors.append(error)

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def errors(self) -> list[CertificateError]:
        return self._errors

    @property
    def warnings(self) -> list[CertificateError]:
        return self._warnings

    def _run_checks(self) -> None:
        self._check_version()
        self._check_serial_number()
        self._check_signature_oid_entries()
        self._check_subject()
        self._check_issuer()

    @property
    def is_valid(self) -> bool:
        if self._was_processed:
            return self._is_valid
        self._run_checks()
        self._is_valid = False if self._errors else True
        self._was_processed = True
        return self._is_valid

    def validate(self) -> bool:
        return self.is_valid

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    def _check_version(self) -> None:
        if self._certificate.version != x509.Version.v3:
            self._add_error(CertificateError.INVALID_VERSION)

    def _check_serial_number(self) -> None:
        if self._certificate.serial_number > SERIAL_MAX_VALUE:
            self._add_error(CertificateError.INVALID_VERSION)
        # TODO: short serial number
        # TODO: parsing with pyasn1 required

    def _check_signature_oid_entries(self) -> None:
        # must be identical
        # TODO: parse with pyans1
        pass

    def _check_subject(self) -> None:
        # PrintableString / UTF8String encoding
        # TODO: parse with pyasn1
        pass

    def _check_issuer(self) -> None:
        # PrintableString / UTF8String encoding
        # TODO: parse with pyasn1
        pass

    def _check_authority_key_identifier(self) -> None:
        try:
            authority_key_identifier = self.certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            self._add_error(CertificateError.EXT_AUTHORITY_KEY_ID_MISSING)
            return

        if authority_key_identifier.critical is True:
            self._add_error(CertificateError.EXT_AUTHORITY_KEY_ID_CRITICAL)

        if authority_key_identifier.value.key_identifier is None:
            self._add_error(CertificateError.EXT_AUTHORITY_KEY_ID_KEY_ID_MISSING)


class CaCertificateValidator(CertificateValidator):
    def _run_checks(self) -> None:
        super()._run_checks()
        self._check_basic_constraints()
        self._check_key_usage()

    def _check_subject_key_identifier(self) -> None:
        try:
            subject_key_identifier = self.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            self._add_error(CertificateError.EXT_SUBJECT_KEY_ID_MISSING)
            return

        if subject_key_identifier.critical is True:
            self._add_error(CertificateError.EXT_SUBJECT_KEY_ID_CRITICAL)

    def _check_key_usage(self) -> None:
        try:
            key_usage = self.certificate.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            self._add_warning(CertificateError.EXT_KEY_USAGE_MISSING)
            return

        if key_usage.critical is False:
            self._add_warning(CertificateError.EXT_KEY_USAGE_NON_CRITICAL)

        if not (key_usage.value.key_cert_sign or key_usage.value.crl_sign or key_usage.value.digital_signature):
            self._add_error(CertificateError.EXT_KEY_USAGE_FLAG_MISSING)

        # TODO: should we return a warning if any other flag is set?

    def _check_certificate_policies(self) -> None:
        try:
            policy_constraints = self.certificate.extensions.get_extension_for_class(x509.PolicyConstraints)
        except x509.ExtensionNotFound:
            return

        if policy_constraints.critical is False:
            self._add_error(CertificateError.EXT_POLICY_CONSTRAINTS_NON_CRITICAL)

        # TODO: MUST: every contained oid is unique
        # TODO: SHOULD: contains no qualifiers
        # TODO: MUST: contain at least one entry

    def _check_policy_mappings(self) -> None:
        try:
            policy_mappings = self.certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.POLICY_MAPPINGS)
        except x509.ExtensionNotFound:
            return

        if policy_mappings.critical is False:
            self._add_warning(CertificateError.EXT_POLICY_MAPPING_NON_CRITICAL)

        # TODO: no mapping to or from anyPolicy allowed

    def _check_subject_alternative_name(self) -> None:
        try:
            subject_alternative_name = self.certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
        except x509.ExtensionNotFound:
            return

        if not self.certificate.subject and subject_alternative_name.critical is False:
            self._add_error(CertificateError.EXT_SUBJECT_ALTERNATIVE_NAME_NON_CRITICAL)

        if self.certificate.subject and subject_alternative_name.critical is True:
            self._add_warning(CertificateError.EXT_SUBJECT_ALTERNATIVE_NAME_CRITICAL)

    def _check_issuer_alternative_name(self) -> None:
        try:
            subject_alternative_name = self.certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
        except x509.ExtensionNotFound:
            return

        if subject_alternative_name.critical is True:
            pass

    def _check_subject_directory_attributes(self) -> None:
        pass

    def _check_basic_constraints(self) -> None:
        try:
            basic_constraints = self.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            self._add_error(CertificateError.EXT_BASIC_CONSTRAINTS_MISSING)
            return

        if basic_constraints.critical is False:
            self._add_error(CertificateError.EXT_BASIC_CONSTRAINTS_NON_CRITICAL)

        if basic_constraints.value.ca is False:
            self._add_error(CertificateError.EXT_BASIC_CONSTRAINTS_NON_CA)

    def _check_name_constraints(self) -> None:
        pass

    def _check_policy_constraints(self) -> None:
        pass

    def _check_extended_key_usage(self) -> None:
        pass

    def _check_crl_distribution_points(self) -> None:
        pass

    def _check_inhibit_any_policy(self) -> None:
        try:
            inhibit_any_policy = self.certificate.extensions.get_extension_for_class(x509.InhibitAnyPolicy)
        except x509.ExtensionNotFound:
            return

        if inhibit_any_policy.critical is False:
            self._add_error(CertificateError.EXT_INHIBIT_ANY_POLICY_NON_CRITICAL)

    def _check_freshest_crl(self) -> None:
        pass

    def _check_authority_information_access(self) -> None:
        pass

    def _check_subject_information_access(self) -> None:
        pass


class RootCaCertificate(CaCertificateValidator):
    def _check_authority_key_identifier(self) -> None:
        try:
            self.certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            return

        super()._check_authority_key_identifier()


# class BsiEndEntityCertificateValidator(BsiX509CertificateValidator):
#     pass


# class BsiCertChainValidator:
#
#     _private_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
#     _certificate: None | x509.Certificate = None
#     _certificate_chain: list[x509.Certificate] = []
#     _additional_certificates: list[x509.Certificate] = []
#
#     def __init__(self, certificate: x509.Certificate, additional_certificates: list[x509.Certificate]) -> None:
#         self._certificate = certificate
#         self._additional_certificates = additional_certificates
#         self._certificate_chain = self._get_cert_chain()
#
#     def _get_cert_chain(self) -> list[x509.Certificate]:
#         pass
#
#     def check_issuing_ca_cert(self) -> None:
#         """Checks if the given certificate is a valid Issuing CA certificate.
#
#         This method uses the BSI X.509 Technical Guideline (TR-02103).
#         Use get_issuing_ca_warnings() to get warnings about entries or the structure
#         that does not comply with best practices.
#
#         Raises:
#             ValueError: If the given certificate is not a valid Issuing CA certificate.
#         """
#
#         if not self._version_is_v3():
#             raise ValueError('The Issuing CA certificate must be Version 3. Compare RFC 5280.')
#
#     def get_issuing_ca_cert_warnings(self) -> None:
#         pass
#
#     def get_generic_warnings(self) -> None:
#         pass
#
#     def _version_is_v3(self) -> bool:
#         if self.certificate.version != x509.Version.v3:
#             return False
#         return True
#
#     # noinspection PyMethodMayBeStatic
#     def _serial_number_is_present(self) -> bool:
#         # Also see RFC 5280 4.1.2.2 Serial Number
#         # TODO: Should we accept all values > 0?
#         # TODO: check how cryptography behaves if serial number is 0 or < 0.
#         if self.certificate.serial_number is None or self.certificate.serial_number == 0:
#             return False
#
#         return True

# def _serial_number_warning(self) -> None | str:
#     # Gives a warning if the first of the 20 octets is 0:
#     if self.certificate.serial_number <= 5_708_990_770_823_839_524_233_143_877_797_980_545_530_986_495:
#         return 'Serial number is shorter than 20 octets. Compare RFC 5280 4.1.2.2 Serial Number.'
