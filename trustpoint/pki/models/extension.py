"""Module that contains X.509 Extension Models."""


from __future__ import annotations

import abc
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.extensions import ExtensionNotFound
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.oid import NameOid, CertificateExtensionOid


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


__all__ = [
    'AttributeTypeAndValue',
    'GeneralNameRFC822Name',
    'GeneralNameDNSName',
    'GeneralNameDirectoryName',
    'GeneralNameUniformResourceIdentifier',
    'GeneralNameIpAddress',
    'GeneralNameRegisteredId',
    'GeneralNameOtherName',
    'CertificateExtension',
    'BasicConstraintsExtension',
    'KeyUsageExtension',
    'GeneralNamesModel',
    'IssuerAlternativeNameExtension',
    'SubjectAlternativeNameExtension'
]


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
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | CertificateExtension:
        """Stores the extension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension):
                The x509.Extension object that contains the extension data of the certificate.

        Returns:
            trustpoint.pki.models.CertificateExtension: The instance of the saved extension.
        """


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


class GeneralNamesModel(models.Model):
    """GeneralNamesModel Model.

    See RFC5280 for more information.
    """

    _general_name_type: str

    critical = models.BooleanField(verbose_name=_('Critical'), editable=False)

    @property
    def extension_oid(self) -> str:
        raise NotImplementedError('This base class (GeneralNamesModel) does not have an extension_oid.')

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
    def _save_rfc822_name(entry: x509.RFC822Name, alt_name_ext: GeneralNamesModel) -> None:
        existing_entry = GeneralNameRFC822Name.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.rfc822_names.add(existing_entry)
        else:
            rfc822_name = GeneralNameRFC822Name(value=entry.value)
            rfc822_name.save()
            alt_name_ext.rfc822_names.add(rfc822_name)
        alt_name_ext.save()

    @staticmethod
    def _save_dns_name(entry: x509.DNSName, alt_name_ext: GeneralNamesModel) -> None:
        existing_entry = GeneralNameDNSName.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.dns_names.add(existing_entry)
        else:
            dns_name = GeneralNameDNSName(value=entry.value)
            dns_name.save()
            alt_name_ext.dns_names.add(dns_name)
        alt_name_ext.save()

    @staticmethod
    def _save_ip_address(entry: x509.IPAddress, alt_name_ext: GeneralNamesModel) -> None:
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
    def _save_uri(entry: x509.UniformResourceIdentifier, alt_name_ext: GeneralNamesModel) -> None:
        existing_entry = GeneralNameUniformResourceIdentifier.objects.filter(value=entry.value).first()
        if existing_entry:
            alt_name_ext.uniform_resource_identifiers.add(existing_entry)
        else:
            uri = GeneralNameUniformResourceIdentifier(value=entry.value)
            uri.save()
            alt_name_ext.uniform_resource_identifiers.add(uri)
        alt_name_ext.save()

    @staticmethod
    def _save_registered_id(entry: x509.RegisteredID, alt_name_ext: GeneralNamesModel) -> None:
        existing_entry = GeneralNameRegisteredId.objects.filter(value=entry.value.dotted_string).first()
        if existing_entry:
            alt_name_ext.registered_ids.add(existing_entry)
        else:
            registered_id = GeneralNameRegisteredId(value=entry.value.dotted_string)
            registered_id.save()
            alt_name_ext.registered_ids.add(registered_id)
        alt_name_ext.save()

    @staticmethod
    def _save_other_name(entry: x509.OtherName, alt_name_ext: GeneralNamesModel) -> None:
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
    def _save_directory_name(entry: x509.DirectoryName, alt_name_ext: GeneralNamesModel) -> None:
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
    def save_general_names(
            cls,
            general_name_ext: SubjectAlternativeNameExtension | IssuerAlternativeNameExtension | AuthorityKeyIdentifierExtension,
            general_names: x509.Extension | list[x509.GeneralName]) \
            -> None | GeneralNamesModel:
        """Stores the GeneralNamesModel in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            alt_name_ext (SubjectAlternativeNameExtension | IssuerAlternativeNameExtension):
                The SubjectAlternativeNameExtension or IssuerAlternativeNameExtension instance to be saved.

            crypto_basic_constraints_extension (x509.CertificateExtension):
                The x509.Extension object that contains all extensions of the certificate.

        Returns:
            trustpoint.pki.models.GeneralNamesModel:
                The instance of the saved GeneralNamesModel.
        """
        if isinstance(general_names, x509.Extension):
            general_names = general_names.value

        for entry in general_names:
            if isinstance(entry, x509.RFC822Name):
                cls._save_rfc822_name(entry=entry, alt_name_ext=general_name_ext)
            if isinstance(entry, x509.DNSName):
                cls._save_dns_name(entry=entry, alt_name_ext=general_name_ext)
            elif isinstance(entry, x509.IPAddress):
                cls._save_ip_address(entry=entry, alt_name_ext=general_name_ext)
            elif isinstance(entry, x509.DirectoryName):
                cls._save_directory_name(entry=entry, alt_name_ext=general_name_ext)
            elif isinstance(entry, x509.UniformResourceIdentifier):
                cls._save_uri(entry=entry, alt_name_ext=general_name_ext)
            elif isinstance(entry, x509.RegisteredID):
                cls._save_registered_id(entry=entry, alt_name_ext=general_name_ext)
            elif isinstance(entry, x509.OtherName):
                cls._save_other_name(entry=entry, alt_name_ext=general_name_ext)

        return general_name_ext

    def __str__(self) -> str:
        return (
            f'{self._general_name_type}(critical={self.critical}, '
            f'oid={self.extension_oid})')


class IssuerAlternativeNameExtension(CertificateExtension, GeneralNamesModel):
    """IssuerAlternativeNameExtension Model.

    See RFC5280 for more information.
    """

    _general_name_type = 'IssuerAlternativeNameExtension'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.ISSUER_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
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
            issuer_alt_name_ext = IssuerAlternativeNameExtension(critical=extension.critical)
            issuer_alt_name_ext.save()

            return super(IssuerAlternativeNameExtension, cls).save_general_names(
                general_name_ext=issuer_alt_name_ext,
                general_names=extension)

        except ExtensionNotFound:
            return None


class SubjectAlternativeNameExtension(CertificateExtension, GeneralNamesModel):
    """SubjectAlternativeNameExtension Model.

    See RFC5280 for more information.
    """

    _general_name_type = 'SubjectAlternativeNameExtension'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
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
            alt_name_ext = SubjectAlternativeNameExtension(critical=extension.critical)
            alt_name_ext.save()

            return super(SubjectAlternativeNameExtension, cls).save_general_names(
                general_name_ext=alt_name_ext,
                general_names=extension)

        except ExtensionNotFound:
            return None

class AuthorityKeyIdentifierExtension(CertificateExtension, GeneralNamesModel):
    """AuthorityKeyIdentifierExtension Model.

    See RFC5280 for more information.
    """

    _general_name_type = 'AuthorityKeyIdentifier'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    key_identifier = models.CharField(
        max_length=256,
        editable=False,
        null=True, blank=True,
        verbose_name='Key Identifier'
    )

    authority_cert_serial_number = models.CharField(
        max_length=256,
        editable=False,
        null=True,
        blank=True,
        verbose_name='Authority Cert Serial Number'
    )

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | AuthorityKeyIdentifierExtension:
        """Stores the AuthorityKeyIdentifierExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension):
                The x509.Extension object that contains the Authority Key Identifier extension of the certificate.

        Returns:
            trustpoint.pki.models.AuthorityKeyIdentifierExtension:
                The instance of the saved AuthorityKeyIdentifierExtension.
        """
        try:
            aki: x509.AuthorityKeyIdentifier = extension.value

            key_identifier = aki.key_identifier.hex().upper() if aki.key_identifier else None
            authority_cert_serial_number = None
            if aki.authority_cert_serial_number is not None:
                authority_cert_serial_number = hex(aki.authority_cert_serial_number)[2:].upper()

            aki_extension = cls(
                critical=extension.critical,
                key_identifier=key_identifier,
                authority_cert_serial_number=authority_cert_serial_number
            )
            aki_extension.save()

            if aki.authority_cert_issuer:
                cls.save_general_names(aki_extension, aki.authority_cert_issuer)

            return aki_extension

        except ExtensionNotFound:
            return None



class SubjectKeyIdentifierExtension(CertificateExtension, models.Model):
    """SubjectKeyIdentifierExtension Model.

    Stores the Subject Key Identifier (SKI) extension of an X.509 certificate.
    """

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()

    # The key_identifier is a hex-encoded, uppercase string representing the SKI
    key_identifier = models.CharField(
        max_length=256,
        editable=False,
        verbose_name='Key Identifier',
        unique=True
    )

    def __str__(self) -> str:
        return f'SubjectKeyIdentifierExtension(key_identifier={self.key_identifier})'

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) \
            -> None | SubjectKeyIdentifierExtension:
        """Stores the SubjectKeyIdentifierExtension in the database.

        Meant to be called within an atomic transaction while storing a certificate.

        Args:
            extension (x509.Extension):
                The x509.Extension object containing the SKI.

        Returns:
            SubjectKeyIdentifierExtension: The saved instance of SubjectKeyIdentifierExtension.
        """
        try:
            ski_value: x509.SubjectKeyIdentifier = extension.value
            key_id_hex = ski_value.digest.hex().upper()

            existing_entry = cls.objects.filter(key_identifier=key_id_hex).first()
            if existing_entry:
                return existing_entry

            ski_extension = cls(key_identifier=key_id_hex)
            ski_extension.save()
            return ski_extension

        except ExtensionNotFound:
            return None



class NoticeReference(models.Model):
    """Represents a NoticeReference as per RFC5280."""
    organization = models.CharField(max_length=200, editable=False, verbose_name='Organization', null=True, blank=True)
    notice_numbers = models.CharField(max_length=1024, editable=False, verbose_name='Notice Numbers', null=True, blank=True)

    def __str__(self):
        return f'{self.organization or "Unknown"}: {self.notice_numbers}'


class UserNotice(models.Model):
    """Represents a UserNotice as per RFC5280."""
    notice_ref = models.ForeignKey(NoticeReference, null=True, blank=True, on_delete=models.CASCADE)
    explicit_text = models.CharField(max_length=200, editable=False, verbose_name='Explicit Text', null=True, blank=True)

    def __str__(self):
        return f'UserNotice: {self.explicit_text or "No Explicit Text"}'


class CPSUriModel(models.Model):
    """Represents a CPS URI as per RFC5280."""
    cps_uri = models.CharField(max_length=2048, editable=False, verbose_name='CPS URI')

    def __str__(self):
        return f'CPS URI: {self.cps_uri}'


class QualifierModel(models.Model):
    """Generic model to represent either a CPS URI or a User Notice."""
    # TODO(BytesWelder): Maybe use cps_uri directly as CharField. Discuss differences
    cps_uri = models.ForeignKey(CPSUriModel, null=True, blank=True, on_delete=models.CASCADE, related_name='qualifiers')
    user_notice = models.ForeignKey(UserNotice, null=True, blank=True, on_delete=models.CASCADE, related_name='qualifiers')

    def __str__(self):
        if self.cps_uri:
            return f'Qualifier: CPS URI - {self.cps_uri}'
        if self.user_notice:
            return f'Qualifier: User Notice - {self.user_notice}'
        return 'Qualifier: Undefined'

    def save(self, *args, **kwargs):
        if self.cps_uri and self.user_notice:
            raise ValueError("Only one of 'cps_uri' or 'user_notice' can be set, not both.")
        super().save(*args, **kwargs)

class PolicyQualifierInfo(models.Model):
    """Represents a PolicyQualifierInfo as per RFC5280."""
    policy_qualifier_id = models.CharField(max_length=256, editable=False, verbose_name='Policy Qualifier ID')
    qualifier = models.ForeignKey(QualifierModel, null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return f'PolicyQualifierInfo: {self.policy_qualifier_id}'


class PolicyInformation(models.Model):
    """Model representing PolicyInformation as per RFC5280."""

    policy_identifier = models.CharField(max_length=256, editable=False, verbose_name='Policy Identifier')
    policy_qualifiers = models.ManyToManyField(PolicyQualifierInfo, blank=True, related_name='policies', editable=False)

    def __str__(self):
        return f'PolicyInformation(policy_identifier={self.policy_identifier})'



class CertificatePoliciesExtension(CertificateExtension, models.Model):
    """CertificatePoliciesExtension Model.

    Stores the certificatePolicies extension as per RFC5280.
    """

    critical = models.BooleanField(verbose_name='Critical', editable=False)

    certificate_policies = models.ManyToManyField(
        PolicyInformation, 
        related_name='certificate_policies', 
        editable=False
    )

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.CERTIFICATE_POLICIES.dotted_string
    extension_oid.fget.short_description = CertificateExtensionOid.get_short_description_str()


    def __str__(self):
        return f"CertificatePoliciesExtension(critical={self.critical}, " \
               f"policies={[policy.policy_identifier for policy in self.certificate_policies.all()]})"

    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | CertificatePoliciesExtension:
        """Stores the CertificatePoliciesExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object that contains the CertificatePolicies.

        Returns:
            CertificatePoliciesExtension: The instance of the saved CertificatePoliciesExtension.
        """
        if not isinstance(extension.value, x509.CertificatePolicies):
            raise ValueError("Expected a CertificatePolicies extension.")

        try:
            policies_extension = cls(critical=extension.critical)
            policies_extension.save()

            for policy_info in extension.value:
                policy_identifier = policy_info.policy_identifier.dotted_string
                policy_information = PolicyInformation.objects.filter(policy_identifier=policy_identifier).first()

                if not policy_information:
                    policy_information = PolicyInformation(policy_identifier=policy_identifier)
                    policy_information.save()

                # Add policy qualifiers if present
                for qualifier in policy_info.policy_qualifiers:
                    if isinstance(qualifier, x509.UserNotice):
                        # Save User Notice
                        notice_reference = qualifier.notice_reference
                        user_notice = UserNotice.objects.create(
                            notice_ref=NoticeReference.objects.create(
                                organization=notice_reference.organization if notice_reference else None,
                                notice_numbers=",".join(map(str, notice_reference.notice_numbers)) if notice_reference else None,
                            ) if notice_reference else None,
                            explicit_text=qualifier.explicit_text,
                        )
                        qualifier_model = QualifierModel(user_notice=user_notice)
                        qualifier_model.save()

                    elif isinstance(qualifier, str):
                        # Save CPS URI
                        cps_uri = CPSUriModel.objects.create(cps_uri=qualifier)
                        qualifier_model = QualifierModel(cps_uri=cps_uri)
                        qualifier_model.save()

                    # Add the qualifier to the policy
                    policy_qualifier_info = PolicyQualifierInfo.objects.create(
                        policy_qualifier_id=qualifier_model.pk,
                        qualifier=qualifier_model,
                    )
                    policy_information.policy_qualifiers.add(policy_qualifier_info)

                policy_information.save()
                policies_extension.certificate_policies.add(policy_information)

            policies_extension.save()
            return policies_extension

        except x509.ExtensionNotFound:
            return None



class KeyPurposeIdModel(models.Model):
    """Represents a KeyPurposeId (OID) used in Extended Key Usage extension."""
    oid = models.CharField(max_length=256, editable=False, verbose_name='Key Purpose OID', unique=True)

    def __str__(self):
        return f'KeyPurposeId({self.oid})'


class ExtendedKeyUsageExtension(models.Model):
    """ExtendedKeyUsageExtension Model.

    As per RFC5280, this extension indicates one or more purposes for which the certified
    public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension.
    """
    critical = models.BooleanField(verbose_name='Critical', editable=False)
    key_purpose_ids = models.ManyToManyField(KeyPurposeIdModel, related_name='extended_key_usages', editable=False)

    def __str__(self) -> str:
        purposes = [k.oid for k in self.key_purpose_ids.all()]
        return f'ExtendedKeyUsageExtension(critical={self.critical}, key_purposes={purposes})'

    @property
    def extension_oid(self) -> str:
        return CertificateExtensionOid.EXTENDED_KEY_USAGE.dotted_string


    @classmethod
    def save_from_crypto_extensions(cls, extension: x509.Extension) -> None | ExtendedKeyUsageExtension:
        """Stores the ExtendedKeyUsageExtension in the database.

        Args:
            extension (x509.Extension): The x509.Extension object that contains the Extended Key Usage.

        Returns:
            ExtendedKeyUsageExtension: The instance of the saved ExtendedKeyUsageExtension.
        """
        if not isinstance(extension.value, x509.ExtendedKeyUsage):
            raise ValueError("Expected an ExtendedKeyUsage extension.")

        try:
            eku_extension = cls(critical=extension.critical)
            eku_extension.save()

            for oid in extension.value:
                oid_str = oid.dotted_string
                key_purpose = KeyPurposeIdModel.objects.filter(oid=oid_str).first()
                if not key_purpose:
                    key_purpose = KeyPurposeIdModel(oid=oid_str)
                    key_purpose.save()

                eku_extension.key_purpose_ids.add(key_purpose)

            eku_extension.save()
            return eku_extension

        except ExtensionNotFound:
            return None
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