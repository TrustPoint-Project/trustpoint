"""Module that contains all models corresponding to the PKI app."""


from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _


from core.oid import SignatureAlgorithmOid, PublicKeyAlgorithmOid, EllipticCurveOid, CertificateExtensionOid, NameOid
from core.serializer import CertificateSerializer, PublicKeySerializer, CertificateCollectionSerializer

from pki.models.text_choice import CertificateStatus
from pki.models.extension import (
    AttributeTypeAndValue,
    BasicConstraintsExtension,
    KeyUsageExtension,
    IssuerAlternativeNameExtension,
    SubjectAlternativeNameExtension
)

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]

log = logging.getLogger('tp.pki')


__all__ = [
    'CertificateModel',
]

class CertificateModel(models.Model):
    """X509 Certificate Model.

    See RFC5280 for more information.
    """

    # ------------------------------------------------- Django Choices -------------------------------------------------

    class Version(models.IntegerChoices):
        """X509 RFC 5280 - Certificate Version."""
        # We only allow version 3 or later if any are available in the future.
        V3 = 2, _('Version 3')

    SignatureAlgorithmOidChoices = models.TextChoices(
        'SIGNATURE_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in SignatureAlgorithmOid])

    PublicKeyAlgorithmOidChoices = models.TextChoices(
        'PUBLIC_KEY_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in PublicKeyAlgorithmOid]
    )

    PublicKeyEcCurveOidChoices = models.TextChoices(
        'PUBLIC_KEY_EC_CURVE_OID', [(x.dotted_string, x.dotted_string) for x in EllipticCurveOid]
    )

    # ----------------------------------------------- Custom Data Fields -----------------------------------------------

    certificate_status = models.CharField(verbose_name=_('Status'), max_length=4, choices=CertificateStatus,
                                          editable=False, default=CertificateStatus.OK)

    # TODO: This is kind of a hack.
    # TODO: This information is already available through the subject relation
    # TODO: Property would not be sortable.
    # TODO: We may want to resolve this later by modifying the queryset within the view
    common_name = models.CharField(
        verbose_name=_('Common Name'),
        max_length=256,
        default=''
    )
    sha256_fingerprint = models.CharField(verbose_name=_('Fingerprint (SHA256)'), max_length=256, editable=False)

    # ------------------------------------------ Certificate Fields (Header) -------------------------------------------

    # OID of the signature algorithm -> dotted_string in DB
    signature_algorithm_oid = models.CharField(
        _('Signature Algorithm OID'),
        max_length=256,
        editable=False,
        choices=SignatureAlgorithmOidChoices)

    # Name of the signature algorithm
    @property
    def signature_algorithm(self) -> str:
        return SignatureAlgorithmOid(self.signature_algorithm_oid).verbose_name

    signature_algorithm.fget.short_description = _('Signature Algorithm')

    # Padding scheme if RSA is used, otherwise None
    @property
    def signature_algorithm_padding_scheme(self) -> str:
        return SignatureAlgorithmOid(self.signature_algorithm_oid).padding_scheme.verbose_name

    signature_algorithm_padding_scheme.fget.short_description = _('Signature Padding Scheme')

    # The DER encoded signature value as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    signature_value = models.CharField(verbose_name=_('Signature Value'), max_length=65536, editable=False)

    # ------------------------------------------ TBSCertificate Fields (Body) ------------------------------------------
    # order of fields, attributes and choices follows RFC5280

    # X.509 Certificate Version (RFC5280)
    version = models.PositiveSmallIntegerField(verbose_name=_('Version'), choices=Version, editable=False)

    # X.509 Certificate Serial Number (RFC5280)
    # This is not part of the subject. It is the serial number of the certificate itself.
    serial_number = models.CharField(verbose_name=_('Serial Number'), max_length=256, editable=False)

    issuer_references = models.ManyToManyField(
        'self',
        verbose_name=_('Issuers'),
        symmetrical=False,
        related_name='issued_certificate_references')

    issuer = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Issuer'),
        related_name='issuer',
        editable=False)

    # The DER encoded issuer as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    issuer_public_bytes = models.CharField(verbose_name=_('Issuer Public Bytes'), max_length=2048, editable=False)

    # The validity entries use datetime objects with UTC timezone.
    not_valid_before = models.DateTimeField(verbose_name=_('Not Valid Before (UTC)'), editable=False)
    not_valid_after = models.DateTimeField(verbose_name=_('Not Valid After (UTC)'), editable=False)

    # Stored as a set of AttributeTypeAndValue objects directly.
    # Hence, looses some information if for example multiple rdns structures were used.
    # However, this suffices for our use-case.
    # Do not use these to compare certificate subjects. Use issuer_public_bytes for this.
    subject = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Subject'),
        related_name='subject',
        editable=False)

    # The DER encoded subject as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    subject_public_bytes = models.CharField(verbose_name=_('Subject Public Bytes'), max_length=2048, editable=False)

    # Subject Public Key Info - Algorithm OID
    spki_algorithm_oid = models.CharField(
        _('Public Key Algorithm OID'),
        max_length=256,
        editable=False,
        choices=PublicKeyAlgorithmOidChoices)

    # Subject Public Key Info - Algorithm Name
    spki_algorithm = models.CharField(
        verbose_name=_('Public Key Algorithm'),
        max_length=256,
        editable=False)

    # Subject Public Key Info - Key Size
    spki_key_size = models.PositiveIntegerField(_('Public Key Size'), editable=False)

    # Subject Public Key Info - Curve OID if ECC, None otherwise
    spki_ec_curve_oid = models.CharField(
        verbose_name=_('Public Key Curve OID (ECC)'),
        max_length=256,
        editable=False,
        choices=PublicKeyEcCurveOidChoices,
        default=EllipticCurveOid.NONE.dotted_string)

    # Subject Public Key Info - Curve Name if ECC, None otherwise
    spki_ec_curve = models.CharField(
        verbose_name=_('Public Key Curve (ECC)'),
        max_length=256,
        editable=False,
        default=EllipticCurveOid.NONE.name)

    # ---------------------------------------------------- Raw Data ----------------------------------------------------

    cert_pem = models.CharField(verbose_name=_('Certificate (PEM)'), max_length=65536, editable=False, unique=True)
    public_key_pem = models.CharField(verbose_name=_('Public Key (PEM, SPKI)'), max_length=65536, editable=False)

    # ------------------------------------------ Trustpoint Creation Data ------------------------------------------

    added_at = models.DateTimeField(verbose_name=_('Added at'), auto_now_add=True)

    # --------------------------------------------- Data Retrieval Methods ---------------------------------------------

    def get_certificate_serializer(self) -> CertificateSerializer:
        return CertificateSerializer(self.cert_pem)

    def get_public_key_serializer(self) -> PublicKeySerializer:
        return PublicKeySerializer(self.public_key_pem)

    # def get_certificate_status(self):
    #     status_mapping = dict(CertificateStatus.choices)
    #     return status_mapping.get(self.certificate_status)

    # TODO: check order of chains
    def get_certificate_chains(self, include_self: bool = True) -> list[list[CertificateModel]]:
        if self.is_self_signed:
            if include_self:
                return [[self]]
            else:
                return [[]]

        cert_chains = []
        for issuer_reference in self.issuer_references.all():
            cert_chains.extend(issuer_reference.get_certificate_chains())

        if include_self:
            for cert_chain in cert_chains:
                cert_chain.append(self)

        return cert_chains

    # TODO: check order of chains
    def get_certificate_chain_serializers(self, include_self: bool = True) -> list[CertificateCollectionSerializer]:
        certificate_chain_serializers = []
        for cert_chain in self.get_certificate_chains(include_self=include_self):
            certificate_chain_serializers.append(CertificateCollectionSerializer(
                [cert.get_certificate_serializer().as_crypto() for cert in cert_chain]))
        return certificate_chain_serializers

    # --------------------------------------------------- Extensions ---------------------------------------------------
    # order of extensions follows RFC5280

    key_usage_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.KEY_USAGE.verbose_name,
        to=KeyUsageExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE)

    subject_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.verbose_name,
        to=SubjectAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    issuer_alternative_name_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.verbose_name,
        to=IssuerAlternativeNameExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE
    )

    basic_constraints_extension = models.ForeignKey(
        verbose_name=CertificateExtensionOid.BASIC_CONSTRAINTS.verbose_name,
        to=BasicConstraintsExtension,
        related_name='certificates',
        editable=False,
        null=True,
        blank=True,
        on_delete=models.CASCADE)

    # ext_authority_key_id = None
    # ext_subject_key_id = None
    # ext_certificate_policies = None
    # ext_policy_mappings = None
    # ext_subject_alternative_name = None
    # ext_issuer_alternative_name = None
    # ext_subject_directory_attributes = None
    # ext_name_constraints = None
    # ext_policy_constraints = None
    # ext_extended_key_usage = None
    # ext_crl_distribution_points = None
    # ext_inhibit_any_policy = None
    # ext_freshest_crl = None

    # Private Internet Access
    # ext_authority_information_access = None
    # ext_subject_information_access = None

    # --------------------------------------------------- Properties ---------------------------------------------------

    @property
    def is_cross_signed(self) -> bool:
        if len(self.issuer_references.all()) > 1:
            return True
        return False

    @property
    def is_self_signed(self) -> bool:
        if len(self.issuer_references.all()) == 1 and self.issuer_references.first() == self:
            return True
        return False

    @property
    def is_ca(self) -> bool:
        if self.basic_constraints_extension and self.basic_constraints_extension.ca:
            return True
        return False

    @property
    def is_root_ca(self) -> bool:
        if self.is_self_signed and self.is_ca:
            return True
        return False

    @property
    def is_end_entity(self) -> bool:
        return not self.is_ca

    def __str__(self) -> str:
        return f'Certificate(CN={self.common_name})'

    @classmethod
    def _get_cert_by_sha256_fingerprint(cls, sha256_fingerprint: str) -> None | CertificateModel:
        sha256_fingerprint = sha256_fingerprint.upper()
        return cls.objects.filter(sha256_fingerprint=sha256_fingerprint).first()

    @staticmethod
    def _get_subject(cert: x509.Certificate) -> list[tuple[str, str]]:
        subject = []
        for rdn in cert.subject.rdns:
            for attr_type_and_value in rdn:
                subject.append(
                    (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
                )
        return subject

    @staticmethod
    def _get_issuer(cert: x509.Certificate) -> list[tuple[str, str]]:
        issuer = []
        for rdn in cert.issuer.rdns:
            for attr_type_and_value in rdn:
                issuer.append(
                    (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
                )
        return issuer

    @staticmethod
    def _get_spki_info(cert: x509.Certificate) -> tuple[PublicKeyAlgorithmOid, int, EllipticCurveOid]:
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.RSA
            spki_ec_curve_oid = EllipticCurveOid.NONE
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.ECC
            spki_ec_curve_oid = EllipticCurveOid[cert.public_key().curve.name.upper()]
        else:
            raise ValueError('Subject Public Key Info contains an unsupported key type.')

        return spki_algorithm_oid, cert.public_key().key_size, spki_ec_curve_oid

    # ---------------------------------------------- Private save methods ----------------------------------------------

    def _save(self, *args, **kwargs) -> None:
        return super().save(*args, **kwargs)

    @classmethod
    def _save_certificate(cls, certificate: x509.Certificate, exist_ok: bool = False) -> 'CertificateModel':

        # ------------------------------------------------ Exist Checks ------------------------------------------------

        # Handles the case in which the certificate is already stored in the database
        cert_in_db = cls._get_cert_by_sha256_fingerprint(certificate.fingerprint(algorithm=hashes.SHA256()).hex())
        if cert_in_db and exist_ok:
            return cert_in_db
        if cert_in_db and not exist_ok:
            log.error(f'Attempted to save certificate {cert_in_db.common_name} already stored in the database.')
            raise ValueError('Certificate already stored in the database.')

        # --------------------------------------------- Custom Data Fields ---------------------------------------------

        sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()

        # ---------------------------------------- Certificate Fields (Header) -----------------------------------------

        signature_algorithm_oid = certificate.signature_algorithm_oid.dotted_string
        signature_value = certificate.signature.hex().upper()

        # ---------------------------------------- TBSCertificate Fields (Body) ----------------------------------------

        version = certificate.version.value
        serial_number = hex(certificate.serial_number)[2:].upper()

        issuer = cls._get_issuer(certificate)
        issuer_public_bytes = certificate.issuer.public_bytes().hex().upper()

        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc

        subject = cls._get_subject(certificate)
        subject_public_bytes = certificate.subject.public_bytes().hex().upper()

        spki_algorithm_oid, spki_key_size, spki_ec_curve_oid = cls._get_spki_info(certificate)

        # -------------------------------------------------- Raw Data --------------------------------------------------

        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()

        public_key_pem = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        # ----------------------------------------- Certificate Model Instance -----------------------------------------

        cert_model = CertificateModel(
            sha256_fingerprint=sha256_fingerprint,
            signature_algorithm_oid=signature_algorithm_oid,
            signature_value=signature_value,
            version=version,
            serial_number=serial_number,
            issuer_public_bytes=issuer_public_bytes,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            subject_public_bytes=subject_public_bytes,
            spki_algorithm_oid=spki_algorithm_oid.dotted_string,
            spki_algorithm=spki_algorithm_oid.name,
            spki_key_size=spki_key_size,
            spki_ec_curve_oid=spki_ec_curve_oid.dotted_string,
            spki_ec_curve=spki_ec_curve_oid.verbose_name,
            cert_pem=cert_pem,
            public_key_pem=public_key_pem,
        )

        # --------------------------------------------- Store in DataBase ----------------------------------------------

        return cls._atomic_save(cert_model=cert_model, certificate=certificate, subject=subject, issuer=issuer)

    # TODO: remove code duplication
    @staticmethod
    def _save_subject(cert_model: CertificateModel, subject: list[tuple[str, str]]) -> None:
        for entry in subject:
            oid, value = entry
            existing_attr_type_and_val = AttributeTypeAndValue.objects.filter(oid=oid, value=value).first()
            if existing_attr_type_and_val:
                cert_model.subject.add(existing_attr_type_and_val)
            else:
                attr_type_and_val = AttributeTypeAndValue(oid=oid, value=value)
                attr_type_and_val.save()
                cert_model.subject.add(attr_type_and_val)

    @staticmethod
    def _save_issuer(cert_model: CertificateModel, issuer: list[tuple[str, str]]) -> None:
        for entry in issuer:
            oid, value = entry
            existing_attr_type_and_val = AttributeTypeAndValue.objects.filter(oid=oid, value=value).first()
            if existing_attr_type_and_val:
                cert_model.issuer.add(existing_attr_type_and_val)
            else:
                attr_type_and_val = AttributeTypeAndValue(oid=oid, value=value)
                attr_type_and_val.save()
                cert_model.issuer.add(attr_type_and_val)

    @staticmethod
    def _save_extensions(cert_model: CertificateModel, cert: x509.Certificate) -> None:
        for extension in cert.extensions:
            if isinstance(extension.value, x509.BasicConstraints):
                cert_model.basic_constraints_extension = \
                    BasicConstraintsExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.KeyUsage):
                cert_model.key_usage_extension = \
                    KeyUsageExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.IssuerAlternativeName):
                cert_model.issuer_alternative_name_extension = \
                    IssuerAlternativeNameExtension.save_from_crypto_extensions(extension)
            elif isinstance(extension.value, x509.SubjectAlternativeName):
                cert_model.subject_alternative_name_extension = \
                    SubjectAlternativeNameExtension.save_from_crypto_extensions(extension)

    @classmethod
    @transaction.atomic
    def _atomic_save(
            cls,
            cert_model: CertificateModel,
            certificate: x509.Certificate,
            subject: list[tuple[str, str]],
            issuer: list[tuple[str, str]]) -> 'CertificateModel':

        cert_model._save()
        for oid, value in subject:
            if oid == NameOid.COMMON_NAME.dotted_string:
                cert_model.common_name = value
        cls._save_subject(cert_model, subject)
        cls._save_issuer(cert_model, issuer)

        cls._save_extensions(cert_model, certificate)
        cert_model._save()  # noqa: SLF001

        # ------------------------------------------ Adding issuer references ------------------------------------------

        issuer_candidates = cls.objects.filter(subject_public_bytes=cert_model.issuer_public_bytes)

        for issuer_candidate in issuer_candidates:
            try:
                certificate.verify_directly_issued_by(
                    issuer_candidate.get_certificate_serializer().as_crypto())
                cert_model.issuer_references.add(issuer_candidate)
                if hasattr(issuer_candidate, 'issuing_ca_model'):
                    issuer_candidate.issuing_ca_model.increment_issued_certificates_count()
            except (ValueError, TypeError, InvalidSignature):
                pass

        # ------------------------------------ Adding issuer references on children ------------------------------------

        issued_candidates = cls.objects.filter(issuer_public_bytes=cert_model.subject_public_bytes)

        for issued_candidate in issued_candidates:
            try:
                issued_candidate.get_certificate_serializer().as_crypto().verify_directly_issued_by(certificate)
                issued_candidate.issuer_references.add(cert_model)
            except (ValueError, TypeError, InvalidSignature):
                pass

        log.info(f'Saved certificate {cert_model.common_name} in the database.')
        return cert_model

    # ---------------------------------------------- Public save methods -----------------------------------------------

    def save(self, *args, **kwargs) -> None:
        """Save method must not be called directly to protect the integrity.

        This method makes sure, save() is not called by mistake.

        Raises:
            NotImplementedError
        """

        raise NotImplementedError(
            '.save() must not be called directly on a Certificate instance to protect the integrity of the database. '
            'Use .save_certificate() or .save_certificate_and_key() passing the required cryptography objects.'
        )

    @classmethod
    def save_certificate(cls, certificate: x509.Certificate, exist_ok: bool = False) -> CertificateModel:
        """Store the certificate in the database.

        Returns:
            trustpoint.pki.models.Certificate: The certificate object that has just been saved.
        """
        return cls._save_certificate(certificate=certificate, exist_ok=exist_ok)
