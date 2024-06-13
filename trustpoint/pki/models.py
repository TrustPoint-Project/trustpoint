"""Module that contains all models corresponding to the PKI app."""


from __future__ import annotations

import abc

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.extensions import ExtensionNotFound
from django.db import models
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from .oid import SignatureAlgorithmOid, PublicKeyAlgorithmOid, EllipticCurveOid, CertificateExtensionOid, NameOid


# ----------------------------------------- Subject / Issuer Field Structures ------------------------------------------

class AttributeTypeAndValue(models.Model):
    """AttributeTypeAndValue Model.

    Used for subject entries as well as the GeneralNameDirectoryName entries within
    the SubjectAlternativeName and IssuerAlternativeName.

    See RFC5280 for more information.
    """
    class Meta:
        unique_together = ('oid', 'value')

    oid = models.CharField(max_length=256, editable=False, verbose_name='OID')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')

    def __str__(self) -> str:
        try:
            name_oid = NameOid(self.oid).full_name
        except ValueError:
            name_oid = self.oid
        return f'{name_oid}={self.value}'


class GeneralNameRFC822Name(models.Model):
    """GeneralNameRFC822Name Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=1024, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        return f'{self.value}'


class GeneralNameDNSName(models.Model):
    """GeneralNameDNSName Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=1024, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        return f'{self.value}'


class GeneralNameDirectoryName(models.Model):
    """GeneralNameDirectoryName Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    names = models.ManyToManyField(
        AttributeTypeAndValue,
        verbose_name=_('Name'),
        editable=False)

    def __str__(self) -> str:
        names = self.names.all()
        string = ''
        for name in names:
            string += f'{str(name)}, '

        return string[:-2]


class GeneralNameUniformResourceIdentifier(models.Model):
    """GeneralNameUniformResourceIdentifier Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value', unique=True)

    def __str__(self) -> str:
        return f'{self.value}'


class GeneralNameIpAddress(models.Model):
    """GeneralNameIpAddress Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    class Meta:
        unique_together = ('ip_type', 'value')

    class IpType(models.TextChoices):
        IPV4_ADDRESS = 'A4', _('IPv4 Address')
        IPV6_ADDRESS = 'A6', _('IPv6 Address')
        IPV4_NETWORK = 'N4', _('IPv4 Network')
        IPV6_NETWORK = 'N6', _('IPv6 Network')

    ip_type = models.CharField(max_length=2, choices=IpType, editable=False, verbose_name='IP Type')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')

    def __str__(self) -> str:
        return f'{self.IpType(self.ip_type).label}:{self.value}'


class GeneralNameRegisteredId(models.Model):
    """GeneralNameRegisteredId Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    value = models.CharField(max_length=256, editable=False, verbose_name='Value')

    def __str__(self) -> str:
        return f'{self.value}'


class GeneralNameOtherName(models.Model):
    """GeneralNameOtherName Model.

    Entries of either SubjectAlternativeNames or IssuerAlternativeNames.

    See RFC5280 for more information.
    """
    class Meta:
        unique_together = ('type_id', 'value')

    type_id = models.CharField(max_length=256, editable=False, verbose_name='OID')
    value = models.CharField(max_length=16384, editable=False, verbose_name='Value')

    def __str__(self) -> str:
        return f'{self.type_id} : {self.value[:10]}...'


class CertificateExtension:
    """Abstract Base Class of Extension Models.

    Due to a Metaclass conflict, this class is not derived from abc.ABC on purpose.
    # TODO: check if this can be rectified
    """

    @classmethod
    @abc.abstractmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | CertificateExtension:
        """Stores the extension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.CertificateExtension: The instance of the saved extension.
        """
        pass


class BasicConstraintsExtension(CertificateExtension, models.Model):
    """BasicConstraintsExtension Model.

    See RFC5280 for more information.
    """

    class Meta:
        unique_together = ('critical', 'ca', 'path_length_constraint')

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.BASIC_CONSTRAINTS.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)

    ca = models.BooleanField(verbose_name=_('CA'), editable=False)
    path_length_constraint = models.PositiveSmallIntegerField(
        verbose_name=_('Path Length Constraint'),
        editable=False,
        null=True,
        blank=True)

    def __str__(self) -> str:
        return (
            f'BasicConstraintsExtension(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | BasicConstraintsExtension:
        """Stores the BasicConstraintsExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.BasicConstraintsExtension: The instance of the saved BasicConstraintsExtension.
        """

        try:
            existing_entry = BasicConstraintsExtension.objects.filter(
                critical=crypto_basic_constraints_extension.critical,
                ca=crypto_basic_constraints_extension.value.ca,
                path_length_constraint=crypto_basic_constraints_extension.value.path_length).first()
            if existing_entry:
                return existing_entry

            basic_constraints_extension = cls()
            basic_constraints_extension.critical = crypto_basic_constraints_extension.critical
            basic_constraints_extension.ca = crypto_basic_constraints_extension.value.ca
            basic_constraints_extension.path_length_constraint = crypto_basic_constraints_extension.value.path_length
            basic_constraints_extension.save()

            return basic_constraints_extension

        except ExtensionNotFound:
            return None


class KeyUsageExtension(CertificateExtension, models.Model):
    """KeyUsageExtension Model.

    See RFC5280 for more information.
    """
    class Meta:
        unique_together = (
            'digital_signature',
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
            'encipher_only',
            'decipher_only')

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.KEY_USAGE.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)

    digital_signature = models.BooleanField(verbose_name=_('Digital Signature'), default=False, editable=False)
    content_commitment = models.BooleanField(verbose_name=_('Content Commitment'), default=False, editable=False)
    key_encipherment = models.BooleanField(verbose_name=_('Key Encipherment'), default=False, editable=False)
    data_encipherment = models.BooleanField(verbose_name=_('Data Encipherment'), default=False, editable=False)
    key_agreement = models.BooleanField(verbose_name=_('Key Agreement'), default=False, editable=False)
    key_cert_sign = models.BooleanField(verbose_name=_('Key Cert Sign'), default=False, editable=False)
    crl_sign = models.BooleanField(verbose_name=_('CRL Sign'), default=False, editable=False)
    encipher_only = models.BooleanField(verbose_name=_('Encipher Only'), default=False, editable=False)
    decipher_only = models.BooleanField(verbose_name=_('Encipher Only'), default=False, editable=False)

    def __str__(self) -> str:
        return (
            f'KeyUsageExtension(critical={self.critical}, '
            f'oid={self.extension_oid})')

    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | KeyUsageExtension:
        """Stores the KeyUsageExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.KeyUsageExtension: The instance of the saved KeyUsageExtension.
        """

        try:
            # noinspection PyProtectedMember
            existing_entry = KeyUsageExtension.objects.filter(
                critical=crypto_basic_constraints_extension.critical,
                digital_signature=crypto_basic_constraints_extension.value.digital_signature,
                content_commitment=crypto_basic_constraints_extension.value.content_commitment,
                key_encipherment=crypto_basic_constraints_extension.value.key_encipherment,
                data_encipherment=crypto_basic_constraints_extension.value.data_encipherment,
                key_agreement=crypto_basic_constraints_extension.value.key_agreement,
                key_cert_sign=crypto_basic_constraints_extension.value.key_cert_sign,
                crl_sign=crypto_basic_constraints_extension.value.crl_sign,
                encipher_only=crypto_basic_constraints_extension.value._encipher_only,
                decipher_only=crypto_basic_constraints_extension.value._decipher_only).first()
            if existing_entry:
                return existing_entry

            key_usage_extension = cls()
            key_usage_extension.critical = crypto_basic_constraints_extension.critical
            key_usage_extension.digital_signature = crypto_basic_constraints_extension.value.digital_signature
            key_usage_extension.content_commitment = crypto_basic_constraints_extension.value.content_commitment
            key_usage_extension.key_encipherment = crypto_basic_constraints_extension.value.key_encipherment
            key_usage_extension.data_encipherment = crypto_basic_constraints_extension.value.data_encipherment
            key_usage_extension.key_agreement = crypto_basic_constraints_extension.value.key_agreement
            key_usage_extension.key_cert_sign = crypto_basic_constraints_extension.value.key_cert_sign
            key_usage_extension.crl_sign = crypto_basic_constraints_extension.value.crl_sign
            # noinspection PyProtectedMember
            key_usage_extension.encipher_only = crypto_basic_constraints_extension.value._encipher_only
            # noinspection PyProtectedMember
            key_usage_extension.decipher_only = crypto_basic_constraints_extension.value._decipher_only
            key_usage_extension.save()
            return key_usage_extension

        except ExtensionNotFound:
            return None


class AlternativeNameExtensionModel(models.Model):
    """AlternativeNameExtensionModel Model.

    See RFC5280 for more information.
    """

    _alternative_name_extension_type: str

    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.KEY_USAGE.dotted_string

    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    rfc822_names = models.ManyToManyField(
        to=GeneralNameRFC822Name,
        verbose_name=_('RFC822 Names'),
        related_name='issuer_alternative_names')

    dns_names = models.ManyToManyField(
        GeneralNameDNSName,
        verbose_name=_('DNS Names'),
        related_name='issuer_alternative_names')

    directory_names = models.ManyToManyField(
        GeneralNameDirectoryName,
        verbose_name=_('Directory Names'),
        related_name='issuer_alternative_names')

    uniform_resource_identifiers = models.ManyToManyField(
        GeneralNameUniformResourceIdentifier,
        verbose_name=_('Uniform Resource Identifiers'),
        related_name='issuer_alternative_names')

    ip_addresses = models.ManyToManyField(
        GeneralNameIpAddress,
        verbose_name=_('IP Addresses'),
        related_name='issuer_alternative_names')

    registered_ids = models.ManyToManyField(
        GeneralNameRegisteredId,
        verbose_name=_('Registered IDs'),
        related_name='issuer_alternative_names')

    other_names = models.ManyToManyField(
        GeneralNameOtherName,
        verbose_name=_('Other Names'),
        related_name='issuer_alternative_names')

    @staticmethod
    def _save_rfc822_name(entry: x509.RFC822Name, alt_name_ext: AlternativeNameExtensionModel) -> None:
        existing_entry = GeneralNameRFC822Name.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.rfc822_names.add(existing_entry)
        else:
            rfc822_name = GeneralNameRFC822Name(value=entry.value)
            rfc822_name.save()
            alt_name_ext.rfc822_names.add(rfc822_name)
        alt_name_ext.save()

    @staticmethod
    def _save_dns_name(entry: x509.DNSName, alt_name_ext: AlternativeNameExtensionModel) -> None:
        existing_entry = GeneralNameDNSName.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.dns_names.add(existing_entry)
        else:
            dns_name = GeneralNameDNSName(value=entry.value)
            dns_name.save()
            alt_name_ext.dns_names.add(dns_name)
        alt_name_ext.save()

    @staticmethod
    def _save_ip_address(entry: x509.IPAddress, alt_name_ext: AlternativeNameExtensionModel) -> None:
        if isinstance(entry.value, IPv4Address):
            ip_type = GeneralNameIpAddress.IpType.IPV4_ADDRESS
        elif isinstance(entry.value, IPv6Address):
            ip_type = GeneralNameIpAddress.IpType.IPV6_ADDRESS
        elif isinstance(entry.value, IPv4Network):
            ip_type = GeneralNameIpAddress.IpType.IPV4_NETWORK
        elif isinstance(entry.value, IPv6Network):
            ip_type = GeneralNameIpAddress.IpType.IPV6_NETWORK
        else:
            raise ValueError(f'Unknown IP address type: {type(entry.value).__name__}.')

        existing_entry = GeneralNameIpAddress.objects.filter(ip_type=ip_type, value=entry.value).first()
        if existing_entry:
            alt_name_ext.ip_addresses.add(existing_entry)
        else:
            ip_address = GeneralNameIpAddress(ip_type=ip_type, value=entry.value)
            ip_address.save()
            alt_name_ext.ip_addresses.add(ip_address)
        alt_name_ext.save()

    @staticmethod
    def _save_uri(entry: x509.UniformResourceIdentifier, alt_name_ext: AlternativeNameExtensionModel) -> None:
        existing_entry = GeneralNameUniformResourceIdentifier.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.uniform_resource_identifiers.add(existing_entry)
        else:
            uri = GeneralNameUniformResourceIdentifier(value=entry.value)
            uri.save()
            alt_name_ext.uniform_resource_identifiers.add(uri)
        alt_name_ext.save()

    @staticmethod
    def _save_registered_id(entry: x509.RegisteredID, alt_name_ext: AlternativeNameExtensionModel) -> None:
        existing_entry = GeneralNameRegisteredId.objects.filter(value=entry.value.dotted_string).first()
        if existing_entry:
            alt_name_ext.registered_ids.add(existing_entry)
        else:
            registered_id = GeneralNameRegisteredId(value=entry.value.dotted_string)
            registered_id.save()
            alt_name_ext.registered_ids.add(registered_id)
        alt_name_ext.save()

    @staticmethod
    def _save_other_name(entry: x509.OtherName, alt_name_ext: AlternativeNameExtensionModel) -> None:
        type_id = entry.type_id.dotted_string
        value = entry.value.hex().upper()
        existing_entry = GeneralNameOtherName.objects.filter(type_id=type_id, value=value).first()
        if existing_entry:
            alt_name_ext.other_names.add(existing_entry)
        else:
            other_name = GeneralNameOtherName(
                type_id=type_id,
                value=value
            )
            other_name.save()
            alt_name_ext.other_names.add(other_name)
        alt_name_ext.save()

    @staticmethod
    def _save_directory_name(entry: x509.DirectoryName, alt_name_ext: AlternativeNameExtensionModel) -> None:
        directory_name = GeneralNameDirectoryName()
        directory_name.save()

        alt_name_ext.directory_names.add(directory_name)
        alt_name_ext.save()

        for name in entry.value:
            existing_entry = AttributeTypeAndValue.objects.filter(oid=name.oid.dotted_string, value=name.value).first()
            if existing_entry:
                directory_name.names.add(existing_entry)
            else:
                attr_type_and_val = AttributeTypeAndValue(oid=name.oid.dotted_string, value=name.value)
                attr_type_and_val.save()
                directory_name.names.add(attr_type_and_val)

        directory_name.save()

    @classmethod
    def save_crypto_extensions(
            cls,
            alt_name_ext: SubjectAlternativeNameExtension | IssuerAlternativeNameExtension,
            crypto_basic_constraints_extension: x509.Extension) \
            -> None | AlternativeNameExtensionModel:
        """Stores the AlternativeNameExtensionModel in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            alt_name_ext (SubjectAlternativeNameExtension | IssuerAlternativeNameExtension):
                The SubjectAlternativeNameExtension or IssuerAlternativeNameExtension instance to be saved.

            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.AlternativeNameExtensionModel:
                The instance of the saved AlternativeNameExtensionModel.
        """

        for entry in crypto_basic_constraints_extension.value:

            if isinstance(entry, x509.RFC822Name):
                cls._save_rfc822_name(entry=entry, alt_name_ext=alt_name_ext)
            if isinstance(entry, x509.DNSName):
                cls._save_dns_name(entry=entry, alt_name_ext=alt_name_ext)
            elif isinstance(entry, x509.IPAddress):
                cls._save_ip_address(entry=entry, alt_name_ext=alt_name_ext)
            elif isinstance(entry, x509.DirectoryName):
                cls._save_directory_name(entry=entry, alt_name_ext=alt_name_ext)
            elif isinstance(entry, x509.UniformResourceIdentifier):
                cls._save_uri(entry=entry, alt_name_ext=alt_name_ext)
            elif isinstance(entry, x509.RegisteredID):
                cls._save_registered_id(entry=entry, alt_name_ext=alt_name_ext)
            elif isinstance(entry, x509.OtherName):
                cls._save_other_name(entry=entry, alt_name_ext=alt_name_ext)

        return alt_name_ext

    def __str__(self) -> str:
        return (
            f'{self._alternative_name_extension_type.capitalize()}AlternativeNameExtension(critical={self.critical}, '
            f'oid={self.extension_oid})')


class IssuerAlternativeNameExtension(CertificateExtension, AlternativeNameExtensionModel):
    """IssuerAlternativeNameExtension Model.

    See RFC5280 for more information.
    """

    _alternative_name_extension_type = 'issuer'

    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | IssuerAlternativeNameExtension:
        """Stores the IssuerAlternativeNameExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.IssuerAlternativeNameExtension:
            The instance of the saved IssuerAlternativeNameExtension.
        """

        try:
            alt_name_ext = IssuerAlternativeNameExtension(critical=crypto_basic_constraints_extension.critical)
            alt_name_ext.save()

            return super(IssuerAlternativeNameExtension, cls).save_crypto_extensions(
                alt_name_ext=alt_name_ext,
                crypto_basic_constraints_extension=crypto_basic_constraints_extension)

        except ExtensionNotFound:
            return None


class SubjectAlternativeNameExtension(CertificateExtension, AlternativeNameExtensionModel):
    """SubjectAlternativeNameExtension Model.

    See RFC5280 for more information.
    """

    _alternative_name_extension_type = 'subject'

    @classmethod
    def save_from_crypto_extensions(cls, crypto_basic_constraints_extension: x509.Extension) \
            -> None | SubjectAlternativeNameExtension:
        """Stores the SubjectAlternativeNameExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.SubjectAlternativeNameExtension:
            The instance of the saved SubjectAlternativeNameExtension.
        """

        try:
            alt_name_ext = SubjectAlternativeNameExtension(critical=crypto_basic_constraints_extension.critical)
            alt_name_ext.save()

            return super(SubjectAlternativeNameExtension, cls).save_crypto_extensions(
                alt_name_ext=alt_name_ext,
                crypto_basic_constraints_extension=crypto_basic_constraints_extension)

        except ExtensionNotFound:
            return None

# class AuthorityKeyIdentifierExtension(CertificateExtension, models.Model):
#     pass
#
#
# class SubjectKeyIdentifierExtension(CertificateExtension, models.Model):
#     pass
#
#
# class ExtendedKeyUsageExtension(CertificateExtension, models.Model):
#     pass
#
#
# class NameConstraintsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class CrlDistributionPointsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class CertificatePoliciesExtension(CertificateExtension, models.Model):
#     pass
#
#
# class AuthorityInformationAccessExtension(CertificateExtension, models.Model):
#     pass
#
#
# class SubjectInformationAccessExtension(CertificateExtension, models.Model):
#     pass
#
#
# class InhibitAnyPolicyExtension(CertificateExtension, models.Model):
#     pass
#
#
# class OcspNoCheckExtension(CertificateExtension, models.Model):
#     pass
#
#
# class TlsFeatureExtension(CertificateExtension, models.Model):
#     pass
#
#
# class CrlNumberExtension(CertificateExtension, models.Model):
#     pass
#
#
# class DeltaCrlIndicatorExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PrecertSignedCertificateTimestampsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PrecertPoisonExtension(CertificateExtension, models.Model):
#     pass
#
#
# class SignedCertificateTimestampsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PolicyConstraintsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class FreshestCrlExtension(CertificateExtension, models.Model):
#     pass
#
#
# class IssuingDistributionPointsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class PolicyMappingsExtension(CertificateExtension, models.Model):
#     pass
#
#
# class SubjectDirectoryAttributesExtension(CertificateExtension, models.Model):
#     pass
#
#
# class MsCertificateTemplateExtension(CertificateExtension, models.Model):
#     pass


class Certificate(models.Model):
    """X509 Certificate Model.

    See RFC5280 for more information.
    """

    # ------------------------------------------------- Django Choices -------------------------------------------------

    class CertificateHierarchyType(models.TextChoices):
        ROOT_CA = 'R', _('Root CA')
        INTERMEDIATE_CA = 'N', _('Intermediate CA')
        ISSUING_CA = 'I', _('Issuing CA')
        END_ENTITY_CERT = 'E', _('End-Entity Certificate')

    class Version(models.IntegerChoices):
        """X509 RFC 5280 - Certificate Version."""
        # We only allow version 3 or later if any are available in the future.
        v3 = 2, _('Version 3')

    SIGNATURE_ALGORITHM_OID = models.TextChoices(
        'SIGNATURE_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in SignatureAlgorithmOid])

    PUBLIC_KEY_ALGORITHM_OID = models.TextChoices(
        'PUBLIC_KEY_ALGORITHM_OID', [(x.dotted_string, x.dotted_string) for x in PublicKeyAlgorithmOid]
    )

    PUBLIC_KEY_EC_CURVE_OID = models.TextChoices(
        'PUBLIC_KEY_EC_CURVE_OID', [(x.dotted_string, x.dotted_string) for x in EllipticCurveOid]
    )

    # ----------------------------------------------- Custom Data Fields -----------------------------------------------

    certificate_hierarchy_type = models.CharField(
        verbose_name=_('Certificate Type'),
        max_length=2,
        choices=CertificateHierarchyType,
        editable=False)

    certificate_hierarchy_depth = models.PositiveSmallIntegerField(verbose_name=_('Hierarchy Depth'), editable=False)

    @property
    def common_name(self) -> str:
        cn = self.subject.filter(oid=NameOid.COMMON_NAME.dotted_string).first()
        if cn:
            return cn.value
        return ''
    common_name.fget.short_description = _('Common Name')

    sha256_fingerprint = models.CharField(verbose_name=_('Fingerprint (SHA256)'), max_length=256, editable=False)

    # ------------------------------------------ Certificate Fields (Header) -------------------------------------------

    # OID of the signature algorithm -> dotted_string in DB
    signature_algorithm_oid = models.CharField(
        _('Signature Algorithm OID'),
        max_length=256,
        editable=False,
        choices=SIGNATURE_ALGORITHM_OID)

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

    # Reference to the issuer certificate object in the model.
    # If the certificate is self-signed / root-ca-certificate it is set to None
    issuer = models.ForeignKey(
        'self',
        verbose_name=_('Issuer'),
        on_delete=models.CASCADE,
        null=True,
        editable=False,
        related_name='issued_certs')

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
        editable=False)

    # The DER encoded subject as hex string. Without prefix, all uppercase, no whitespace / trimmed.
    subject_public_bytes = models.CharField(verbose_name=_('Subject Public Bytes'), max_length=2048, editable=False)

    # Subject Public Key Info - Algorithm OID
    spki_algorithm_oid = models.CharField(
        _('Public Key Algorithm OID'),
        max_length=256,
        editable=False,
        choices=PUBLIC_KEY_ALGORITHM_OID)

    # Subject Public Key Info - Algorithm Name
    @property
    def spki_algorithm(self) -> str:
        return PublicKeyAlgorithmOid(self.spki_algorithm_oid).verbose_name
    spki_algorithm.fget.short_description = _('Public Key Algorithm')

    # Subject Public Key Info - Key Size
    spki_key_size = models.PositiveIntegerField(_('Public Key Size'), editable=False)

    # Subject Public Key Info - Curve OID if ECC, None otherwise
    spki_ec_curve_oid = models.CharField(
        _('Public Key Curve OID (ECC)'),
        max_length=256,
        editable=False,
        choices=PUBLIC_KEY_EC_CURVE_OID,
        default=EllipticCurveOid.NONE.dotted_string)

    # Subject Public Key Info - Curve Name if ECC, None otherwise
    @property
    def spki_ec_curve(self) -> str:
        return EllipticCurveOid(self.spki_ec_curve_oid).name
    spki_ec_curve.fget.short_description = _('Public Key Curve (ECC)')

    # TODO: Unique Identifiers (even if deprecated in X.509 v3)

    # ---------------------------------------------------- Raw Data ----------------------------------------------------

    cert_pem = models.CharField(verbose_name=_('Certificate (PEM)'), max_length=65536, editable=False, unique=True)

    public_key_pem = models.CharField(verbose_name=_('Public Key (PEM, SPKI)'), max_length=65536, editable=False)

    private_key_pem = models.CharField(
        verbose_name=_('Private Key (PEM)'),
        max_length=65536,
        editable=False,
        null=True,
        blank=True,
        unique=True)

    # --------------------------------------------- Data Retrieval Methods ---------------------------------------------
    def get_cert_as_pem(self) -> str:
        """Retrieves the certificate as PEM string.

        Returns:
            str: Certificate as PEM string.
        """
        return self.cert_pem

    def get_cert_as_der(self) -> bytes:
        """Retrieves the certificate as DER bytes.

        Returns:
            bytes: Certificate as DER bytes.
        """
        return x509.load_pem_x509_certificate(self.cert_pem.encode()).public_bytes(encoding=serialization.Encoding.DER)

    def get_cert_as_crypto(self) -> x509.Certificate:
        """Retrieves the certificate as cryptography.x509.Certificate object

        Returns:
            cryptography.x509.Certificate: Certificate as cryptography.x509.Certificate object.
        """
        return x509.load_pem_x509_certificate(self.cert_pem.encode())

    def get_public_key_as_pem(self) -> str:
        """Retrieves the public key as PEM string.

        Returns:
            str: Public key as PEM string.

        """
        return self.public_key_pem

    def get_public_key_as_der(self) -> bytes:
        """Retrieves the public key as DER encoded bytes.

        Returns:
            bytes: Public key as DER encoded bytes.
        """
        return serialization.load_pem_public_key(self.public_key_pem.encode()).public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key_as_crypto(self) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        """Retrieves the public key as cryptography public key object.

        Returns:
            rsa.RSAPublicKey | ec.EllipticCurvePublicKey: Public key as cryptography public key object.
        """
        return serialization.load_pem_public_key(self.public_key_pem.encode())

    def get_private_key_as_crypto(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """Retrieves the private key as cryptography public key object.

        Returns:
            rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey: Public key as cryptography private key object.
        """
        return serialization.load_pem_private_key(self.private_key_pem.encode(), password=None)

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

    def __str__(self) -> str:
        subject_common_name = self.common_name
        return f'Certificate(CN={subject_common_name})'

    @classmethod
    def _cert_in_db(cls, cert: x509.Certificate) -> None | Certificate:
        sha256_fingerprint = cert.fingerprint(algorithm=hashes.SHA256()).hex().upper()
        return cls.objects.filter(sha256_fingerprint=sha256_fingerprint).first()

    @staticmethod
    def _cert_is_root_ca(cert: x509.Certificate) -> bool:
        # TODO: proper validation of signature, ...
        return cert.subject.public_bytes() == cert.issuer.public_bytes()

    @classmethod
    def _get_issuer(cls, cert: x509.Certificate) -> Certificate:
        # TODO: utilize extensions Key Identifier
        # TODO: verify signature
        # TODO: handle multiple certificate with equal subjects
        # if len(possible_issuers) > 1:
        #     pass

        possible_issuers = cls.objects.filter(subject_public_bytes=cert.issuer.public_bytes().hex().upper())
        if not possible_issuers:
            raise ValueError(f'No issuers found for {cert.subject.rfc4514_string()}.')

        return possible_issuers[0]

    @staticmethod
    def _get_private_key_value(priv_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> None | str:
        if priv_key is None:
            return None
        else:
            return priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

    @classmethod
    def _get_certificate_hierarchy_type_and_depth(
            cls,
            cert: x509.Certificate,
            issuer: None | Certificate) -> tuple[CertificateHierarchyType, int]:
        if issuer is None:
            return cls.CertificateHierarchyType.ROOT_CA, 0

        certificate_hierarchy_depth = issuer.certificate_hierarchy_depth + 1

        try:
            basic_constraints_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            # TODO: Handle the case where the Certificate does not have a BasicConstraints Extension
            raise ValueError('Certificate does not have a BasicConstraints Extension.')

        if basic_constraints_ext.value.ca:
            if basic_constraints_ext.value.path_length == 0:
                return cls.CertificateHierarchyType.ISSUING_CA, certificate_hierarchy_depth
            else:
                return cls.CertificateHierarchyType.INTERMEDIATE_CA, certificate_hierarchy_depth

        return cls.CertificateHierarchyType.END_ENTITY_CERT, certificate_hierarchy_depth

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
    def _get_spki_info(cert: x509.Certificate) -> tuple[str, int, str]:
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.RSA.dotted_string
            spki_ec_curve_oid = EllipticCurveOid.NONE.dotted_string
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            spki_algorithm_oid = PublicKeyAlgorithmOid.EC.dotted_string
            spki_ec_curve_oid = EllipticCurveOid[cert.public_key().curve.name.upper()].dotted_string
        else:
            raise ValueError('Subject Public Key Info contains an unsupported key type.')

        return spki_algorithm_oid, cert.public_key().key_size, spki_ec_curve_oid

    # ---------------------------------------------- Private save methods ----------------------------------------------

    def _save(self, *args, **kwargs) -> None:
        return super().save(*args, **kwargs)

    @classmethod
    def _save_certificate_and_key(
            cls,
            cert: x509.Certificate,
            priv_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
            exist_ok: bool = False) -> 'Certificate':

        # ------------------------------------------------ Exist Checks ------------------------------------------------

        # Handles the case in which the certificate is already stored in the database
        cert_in_db = cls._cert_in_db(cert=cert)
        if cert_in_db and exist_ok:
            return cert_in_db
        if cert_in_db and not exist_ok:
            raise ValueError('Certificate already stored in the database.')

        # Tries to get the issuer of the certificate to be saved.
        if cls._cert_is_root_ca(cert=cert):
            issuer = None
        else:
            issuer = cls._get_issuer(cert=cert)

        # --------------------------------------------- Custom Data Fields ---------------------------------------------

        certificate_hierarchy_type, certificate_hierarchy_depth = cls._get_certificate_hierarchy_type_and_depth(
            cert=cert, issuer=issuer)
        certificate_hierarchy_type = certificate_hierarchy_type.value

        sha256_fingerprint = cert.fingerprint(algorithm=hashes.SHA256()).hex().upper()

        # ---------------------------------------- Certificate Fields (Header) -----------------------------------------

        signature_algorithm_oid = cert.signature_algorithm_oid.dotted_string
        signature_value = cert.signature.hex().upper()

        # ---------------------------------------- TBSCertificate Fields (Body) ----------------------------------------

        version = cert.version.value
        serial_number = hex(cert.serial_number)[2:].upper()

        # issuer is set in section 'Exist Checks'
        issuer_public_bytes = cert.issuer.public_bytes().hex().upper()

        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        subject = cls._get_subject(cert=cert)
        subject_public_bytes = cert.subject.public_bytes().hex().upper()

        spki_algorithm_oid, spki_key_size, spki_ec_curve_oid = cls._get_spki_info(cert=cert)

        # -------------------------------------------------- Raw Data --------------------------------------------------

        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()

        public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        priv_key_pem = cls._get_private_key_value(priv_key=priv_key)

        # ----------------------------------------- Certificate Model Instance -----------------------------------------

        cert_model = Certificate(
            certificate_hierarchy_type=certificate_hierarchy_type,
            certificate_hierarchy_depth=certificate_hierarchy_depth,
            sha256_fingerprint=sha256_fingerprint,
            signature_algorithm_oid=signature_algorithm_oid,
            signature_value=signature_value,
            version=version,
            serial_number=serial_number,
            issuer=issuer,
            issuer_public_bytes=issuer_public_bytes,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            subject_public_bytes=subject_public_bytes,
            spki_algorithm_oid=spki_algorithm_oid,
            spki_key_size=spki_key_size,
            spki_ec_curve_oid=spki_ec_curve_oid,
            cert_pem=cert_pem,
            public_key_pem=public_key_pem,
            private_key_pem=priv_key_pem
        )

        # --------------------------------------------- Store in DataBase ----------------------------------------------

        return cls._atomic_save(cert_model=cert_model, cert=cert, subject=subject)

    @staticmethod
    def _save_subject(cert_model: Certificate, subject: list[tuple[str, str]]) -> None:
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
    def _save_extensions(cert_model: Certificate, cert: x509.Certificate) -> None:
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
            cert_model: Certificate,
            cert: x509.Certificate,
            subject: list[tuple[str, str]]) -> 'Certificate':

        cert_model._save()
        cls._save_subject(cert_model, subject)
        cls._save_extensions(cert_model, cert)
        cert_model._save()

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
    def save_certificate_and_key(
            cls,
            cert: x509.Certificate,
            priv_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = None) -> Certificate:
        """Store the certificate and corresponding private key in the database and / or secure storage.

        Returns:
            trustpoint.pki.models.Certificate: The certificate object that has just been saved.
        """
        return cls._save_certificate_and_key(cert=cert, priv_key=priv_key)

    @classmethod
    def save_certificate(cls, cert: x509.Certificate) -> Certificate:
        """Store the certificate in the database.

        Returns:
            trustpoint.pki.models.Certificate: The certificate object that has just been saved.
        """
        return cls._save_certificate_and_key(cert=cert, priv_key=None)


class TrustStore(models.Model):
    unique_name = models.CharField(max_length=30, editable=False)
    leaf_certs = models.ManyToManyField(Certificate, related_name='truststores', verbose_name='Leaf Certificates')

    def __str__(self) -> str:
        return f'TrustStore(name={self.unique_name})'

    @classmethod
    def save_trust_store(cls, unique_name, trust_store: list[x509.Certificate]) -> None:
        if cls.objects.filter(unique_name=unique_name).exists():
            raise ValueError(f'A Trust-Store with the unique name {unique_name} already exists.')

        subjects = [cert.subject.public_bytes() for cert in trust_store]
        issuers = [cert.issuer.public_bytes() for cert in trust_store]
        last_cert_subjects_in_chains = [subject for subject in subjects if subject not in issuers]
        leaf_certs = [
            cert for cert in trust_store if cert.subject.public_bytes() in last_cert_subjects_in_chains]
        cert_chains = []

        for leaf_cert in leaf_certs:
            cert_chain = [leaf_cert]
            while True:
                if leaf_cert.subject.public_bytes() == leaf_cert.issuer.public_bytes():
                    break
                for cert in trust_store:
                    if cert.subject.public_bytes() == leaf_cert.issuer.public_bytes():
                        cert_chain.append(cert)
                        leaf_cert = cert
                        break
                else:
                    raise ValueError('Trust-Store contains orphaned certificates.')

            cert_chains.append(cert_chain)

        cls._save_trust_store(unique_name=unique_name, cert_chains=cert_chains)

    @classmethod
    @transaction.atomic
    def _save_trust_store(
            cls,
            unique_name,
            cert_chains: list[list[x509.Certificate]]) -> None:

        trust_store = TrustStore(unique_name=unique_name)
        trust_store.save()

        # TODO: check via sha256 fingerprint instead of subject
        for cert_chain in cert_chains:
            c = None
            for cert in reversed(cert_chain):
                if Certificate.objects.filter(subject_public_bytes=cert.subject.public_bytes().hex().upper()).exists():
                    continue
                c = Certificate.save_certificate(cert=cert)
            trust_store.leaf_certs.add(c)

        trust_store.save()
