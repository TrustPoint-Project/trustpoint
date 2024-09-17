"""Module that contains all models corresponding to the PKI app."""


from __future__ import annotations

import abc
import logging
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.extensions import ExtensionNotFound
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from .issuing_ca import UnprotectedLocalIssuingCa
from .oid import CertificateExtensionOid, EllipticCurveOid, NameOid, PublicKeyAlgorithmOid, SignatureAlgorithmOid
from .serializer import CertificateCollectionSerializer, CertificateSerializer, PublicKeySerializer
from .validator.field import UniqueNameValidator

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]

log = logging.getLogger('tp.pki')


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

    @property
    def abbreviation(self) -> str:
        return NameOid(self.oid).abbreviation

    @property
    def verbose_name(self) -> str:
        return NameOid(self.oid).verbose_name


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
        return f'OID: {self.type_id}, DER: {self.value[:10]}...'


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
    decipher_only = models.BooleanField(verbose_name=_('Decipher Only'), default=False, editable=False)

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
        raise NotImplementedError('This base class (AlternativeNameExtensionModel) does not have an extension_oid.')

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

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

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

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

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

class ReasonCode(models.TextChoices):
    """Revocation reasons per RFC 5280"""
    UNSPECIFIED = 'unspecified', _('Unspecified')
    KEY_COMPROMISE = 'keyCompromise', _('Key Compromise')
    CA_COMPROMISE = 'cACompromise', _('CA Compromise')
    AFFILIATION_CHANGED = 'affiliationChanged', _('Affiliation Changed')
    SUPERSEDED = 'superseded', _('Superseded')
    CESSATION = 'cessationOfOperation', _('Cessation of Operation')
    CERTIFICATE_HOLD = 'certificateHold', _('Certificate Hold')
    PRIVILEGE_WITHDRAWN = 'privilegeWithdrawn', _('Privilege Withdrawn')
    AA_COMPROMISE = 'aACompromise', _('AA Compromise')
    REMOVE_FROM_CRL = 'removeFromCRL', _('Remove from CRL')


class CertificateModel(models.Model):
    """X509 Certificate Model.

    See RFC5280 for more information.
    """

    # ------------------------------------ Reference Counter for delete operations  ------------------------------------

    # TODO

    # ------------------------------------------------- Django Choices -------------------------------------------------

    class CertificateStatus(models.TextChoices):
        OK = 'O', _('OK')
        REVOKED = 'R', _('Revoked')
        # EXPIRED = 'E', _('Expired')
        # NOT_YET_VALID = 'N', _('Not Yet Valid')

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

    certificate_status = models.CharField(verbose_name=_('Status'), max_length=2, choices=CertificateStatus,
                                          editable=False, default=CertificateStatus.OK)

    revocation_reason = models.CharField(
        verbose_name=_('Revocation reason'),
        max_length=30,
        choices=ReasonCode,
        editable=True,
        default=ReasonCode.UNSPECIFIED)

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

    # TODO: check order of chains
    def get_certificate_chains(self, include_self: bool = True) -> list[list[CertificateModel]]:
        if self.is_root_ca:
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

    @transaction.atomic
    def revoke(self, revocation_reason: ReasonCode) -> None:
        """Revokes the certificate."""
        self.certificate_status = self.CertificateStatus.REVOKED
        self.revocation_reason = revocation_reason
        qs = self.issuer_references.all()
        if qs:
            for entry in qs:
                issuing_ca = entry.issuing_ca_model
                rc = RevokedCertificate(cert=self)
                rc.issuing_ca = issuing_ca
                rc.save()
            self._save()
            if issuing_ca.auto_crl:
                issuing_ca.get_issuing_ca().generate_crl()

    def remove_private_key(self):
        self.private_key = None
        self._save()

# ------------------------------------------------- Issuing CA Models --------------------------------------------------

class IssuingCaModel(models.Model):
    """Issuing CA model."""

    unique_name = models.CharField(
        verbose_name=f'Unique Name',
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True,
        editable=False
    )

    root_ca_certificate = models.ForeignKey(
        to=CertificateModel,
        verbose_name=_('Root CA Certificate'),
        on_delete=models.DO_NOTHING,
        related_name='root_ca_certificate',
        editable=False
    )

    intermediate_ca_certificates = models.ManyToManyField(
        to=CertificateModel,
        verbose_name=_('Intermediate CA Certificates'),
        through='CertificateChainOrderModel')

    issuing_ca_certificate = models.OneToOneField(
        to=CertificateModel,
        verbose_name=_('Issuing CA Certificate'),
        on_delete=models.DO_NOTHING,
        related_name='issuing_ca_model',
        editable=False)

    private_key_pem = models.CharField(
        verbose_name=_('Private Key (PEM)'),
        max_length=65536,
        editable=False,
        null=True,
        blank=True,
        unique=True)

    added_at = models.DateTimeField(verbose_name=_('Added at'), auto_now_add=True)

    # TODO: pkcs11_private_key_access -> Foreignkey

    # TODO: remote_ca_config -> ForeignKey

    auto_crl = models.BooleanField(default=True, verbose_name='Generate CRL upon certificate revocation.')

    next_crl_generation_time = models.IntegerField(default=(24*60))

    issued_certificates_count = models.PositiveIntegerField(default=0, editable=False)

    def __str__(self) -> str:
        return self.unique_name

    def get_issuing_ca_certificate(self) -> CertificateModel:
        return self.issuing_ca_certificate

    def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
        return self.issuing_ca_certificate.get_certificate_serializer()

    def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
        return self.issuing_ca_certificate.get_public_key_serializer()

    def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
        # TODO: through table -> order_by order
        cert_chain = [self.root_ca_certificate]
        # print(self.intermediate_ca_certificates.all())
        # cert_chain.extend(self.intermediate_ca_certificates.all().order_by('order').asc())
        cert_chain.append(self.issuing_ca_certificate)
        return cert_chain

    def get_issuing_ca_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(
            [cert.get_certificate_serializer().as_crypto() for cert in self.get_issuing_ca_certificate_chain()])

    def get_issuing_ca(self) -> UnprotectedLocalIssuingCa:
        if self.private_key_pem:
            return UnprotectedLocalIssuingCa(self)
        raise RuntimeError('Unexpected error occurred. No matching IssuingCa object found.')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def increment_issued_certificates_count(self) -> None:
        """Increments issued_certificates_count by one"""
        self.issued_certificates_count = models.F('issued_certificates_count') + 1
        self.save(update_fields=['issued_certificates_count'])


class CertificateChainOrderModel(models.Model):

    class Meta:
        unique_together = ('order', 'issuing_ca')

    order = models.PositiveSmallIntegerField(verbose_name=_('Intermediate CA Index (Order)'), editable=False)
    certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.CASCADE,
        editable=False,
        related_name='issuing_ca_cert_chains')
    issuing_ca = models.ForeignKey(IssuingCaModel, on_delete=models.CASCADE, editable=False)

    def get_issuing_ca(
            self,
            unprotected_local_issuing_ca_class: type(UnprotectedLocalIssuingCa) = UnprotectedLocalIssuingCa
    ) -> IssuingCaModel:
        return unprotected_local_issuing_ca_class(self)

    def __str__(self):
        return f'CertificateChainOrderModel({self.certificate.common_name})'


class DomainModel(models.Model):
    """Endpoint Profile model."""

    unique_name = models.CharField(
        f'Unique Name',
        max_length=100,
        unique=True,
        validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_('Issuing CA'),
        related_name='domain',
    )

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        return self.unique_name

    def get_url_path_segment(self):
        """@BytesWelder: I don't know what we need this for. @Alex mentioned this in his doc.

        Returns:
            str:
                URL path segment.
        """
        return self.unique_name.lower().replace(' ', '-')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class RevokedCertificate(models.Model):
    """Certificate Revocation model."""
    cert = models.ForeignKey(CertificateModel, on_delete=models.PROTECT)
    revocation_datetime = models.DateTimeField(auto_now_add=True, help_text='Timestamp when certificate was revoked.')
    issuing_ca = models.ForeignKey(
        IssuingCaModel, on_delete=models.PROTECT, related_name='revoked_certificates', help_text='Name of Issuing CA.')

    def __str__(self) -> str:
        """Human-readable string when Certificate got revoked

        Returns:
            str:
                CRL as PEM String
        """
        return f"{self.cert.serial_number} - Revoked on {self.revocation_datetime.strftime('%Y-%m-%d %H:%M:%S')}"


class CRLStorage(models.Model):
    """Storage of CRLs."""
    # crl = models.CharField(max_length=4294967296)
    crl = models.TextField(editable=False)
    created_at = models.DateTimeField(editable=False)
    ca = models.ForeignKey(IssuingCaModel, on_delete=models.CASCADE)

    def __str__(self) -> str:
        """PEM representation of CRL

        Returns:
            str:
                CRL as PEM String
        """
        return f'CrlStorage(IssuingCa({self.ca.unique_name}))'

    def save_crl_in_db(self, crl: str, ca: IssuingCaModel):
        """Saving crl in Database

        Returns:
            bool:
                True
        """
        self.crl = crl
        self.ca = ca
        self.save()

    @staticmethod
    def get_crl(ca: IssuingCaModel) -> None | str:
        result = CRLStorage.get_crl_object(ca)
        if result:
            return result.crl
        return None

    @staticmethod
    def get_crl_object(ca: IssuingCaModel) -> None | CRLStorage:
        try:
            return CRLStorage.objects.filter(ca=ca).latest('created_at')
        except CRLStorage.DoesNotExist:
            return None


class TrustStoreModel(models.Model):

    unique_name = models.CharField(
        verbose_name=f'Unique Name',
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True
    )

    certificates = models.ManyToManyField(
        to=CertificateModel,
        verbose_name=_('Intermediate CA Certificates'),
        through='TrustStoreOrderModel')

    @property
    def number_of_certificates(self) -> int:
        return len(self.certificates.all())

    def __str__(self) -> str:
        return f'TrustStoreModel({self.unique_name})'

    def get_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(
            [cert_model.get_certificate_serializer() for cert_model in self.certificates.all()]
        )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class TrustStoreOrderModel(models.Model):

    class Meta:
        unique_together = ('order', 'trust_store')

    order = models.PositiveSmallIntegerField(verbose_name=_('Trust Store Certificate Index (Order)'), editable=False)
    certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.CASCADE,
        editable=False,
        related_name='trust_store_components')
    trust_store = models.ForeignKey(TrustStoreModel, on_delete=models.CASCADE, editable=False)
