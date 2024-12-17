from __future__ import annotations

import ipaddress

from django.db import models    # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from django.contrib.contenttypes.fields import GenericForeignKey   # type: ignore[import-untyped]
from django.contrib.contenttypes.models import ContentType # type: ignore[import-untyped]
from core.validator.field import UniqueNameValidator
from core.serializer import CredentialSerializer, PrivateKeySerializer
from cryptography import x509
from cryptography.x509 import oid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import datetime

from pki.models import CertificateModel, DomainModel, CredentialModel


class DeviceModel(models.Model):

    def _generate_private_key(self) -> PrivateKeySerializer:
        issuing_ca_private_key = self.domain.issuing_ca.credential.get_private_key()
        if isinstance(issuing_ca_private_key, rsa.RSAPrivateKey):
            key_size = issuing_ca_private_key.key_size
            return PrivateKeySerializer(
                rsa.generate_private_key(key_size=key_size, public_exponent=65537)
            )
        if isinstance(issuing_ca_private_key, ec.EllipticCurvePrivateKey):
            curve = issuing_ca_private_key.curve
            return PrivateKeySerializer(
                ec.generate_private_key(curve=curve)
            )
        raise ValueError('Cannot build the domain credential, unknown key type found.')

    def _get_hash_algorithm_from_issuing_ca_credential(self) -> hashes.SHA256 | hashes.SHA384:
        hash_algorithm = self.domain.issuing_ca.credential.get_certificate().signature_hash_algorithm
        if isinstance(hash_algorithm, hashes.SHA256):
            return hashes.SHA256()
        if isinstance(hash_algorithm, hashes.SHA384):
            return hashes.SHA384()
        raise ValueError('Cannot build the domain credential, unknown hash algorithm found.')

    def issue_domain_credential(self) -> CredentialSerializer:
        domain_credential_private_key = self._generate_private_key()
        hash_algorithm = self._get_hash_algorithm_from_issuing_ca_credential()
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Trustpoint Device Credential'),
            x509.NameAttribute(
                x509.NameOID.DN_QUALIFIER,
                f'trustpoint.{self.unique_name}.{self.domain.unique_name}.local'),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number)
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + (one_day * 365))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(
            domain_credential_private_key.public_key_serializer.as_crypto())
        domain_certificate = certificate_builder.sign(
            private_key=domain_credential_private_key.as_crypto(),
            algorithm=hash_algorithm
        )

        certificate = CertificateModel.save_certificate(domain_certificate)
        issued_domain_credential = IssuedDomainCredentialModel(
            issued_domain_credential_certificate=certificate,
            device=self,
            domain=self.domain
        )
        issued_domain_credential.save()

        self.onboarding_status = self.OnboardingStatus.ONBOARDED
        self.save()

        return CredentialSerializer(
            (
                domain_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

    @staticmethod
    def _add_tls_client_cert_extensions(
            certificate_builder: x509.CertificateBuilder,
            application_credential_private_key: PrivateKeySerializer,
            issuing_ca_private_key: PrivateKeySerializer) -> x509.CertificateBuilder:
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuing_ca_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(application_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        return certificate_builder

    @staticmethod
    def _add_tls_server_cert_extensions(
            certificate_builder: x509.CertificateBuilder,
            application_credential_private_key: PrivateKeySerializer,
            issuing_ca_private_key: PrivateKeySerializer,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str]) -> x509.CertificateBuilder:

        # TODO(AlexHx8472): Set key usage according to cipher suite used -> BSI technical guideline
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuing_ca_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                application_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )

        san = []
        for ipv4_address in ipv4_addresses:
            san.append(x509.IPAddress(ipv4_address))
        for ipv6_address in ipv6_addresses:
            san.append(x509.IPAddress(ipv6_address))
        for domain_name in domain_names:
            san.append(x509.DNSName(domain_name))
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(san),
            critical=True
        )
        return certificate_builder

    def issue_application_credential(
            self,
            subject: dict[x509.ObjectIdentifier, str],
            validity_days: int,
            certificate_type: IssuedApplicationCertificateModel.ApplicationCertificateType,
            ipv4_addresses: None | list[ipaddress.IPv4Address] = None,
            ipv6_addresses: None | list[ipaddress.IPv6Address] = None,
            domain_names: None | list[str] = None) -> CredentialSerializer:

        issuing_ca_private_key = self.domain.issuing_ca.credential.get_private_key_serializer()
        application_credential_private_key = self._generate_private_key()
        hash_algorithm = self._get_hash_algorithm_from_issuing_ca_credential()
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(key, value) for key, value in subject.items()
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + (one_day * validity_days))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(
            application_credential_private_key.public_key_serializer.as_crypto())

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False
        )

        if certificate_type == IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_CLIENT:
            certificate_builder = self._add_tls_client_cert_extensions(
                certificate_builder=certificate_builder,
                application_credential_private_key=application_credential_private_key,
                issuing_ca_private_key=issuing_ca_private_key)
        if certificate_type == IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_SERVER:
            certificate_builder = self._add_tls_server_cert_extensions(
                certificate_builder=certificate_builder,
                application_credential_private_key=application_credential_private_key,
                issuing_ca_private_key=issuing_ca_private_key,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                domain_names=domain_names
            )

        domain_certificate = certificate_builder.sign(
            private_key=issuing_ca_private_key.as_crypto(),
            algorithm=hash_algorithm
        )
        certificate = CertificateModel.save_certificate(domain_certificate)

        issued_application_certificate = IssuedApplicationCertificateModel(
            device=self,
            domain=self.domain,
            issued_application_certificate=certificate,
            issued_application_certificate_type=certificate_type
        )
        issued_application_certificate.save()

        return CredentialSerializer(
            (
                application_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

    def __str__(self) -> str:
        return f'DeviceModel(unique_name={self.unique_name})'


    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        NO_ONBOARDING = 0, _('No Onboarding')
        MANUAL = 1, _('Manual download')
        BROWSER = 2, _('Browser download')
        CLI = 3, _('Device CLI')
        TP_CLIENT_PW = 4, _('Trustpoint Client')
        AOKI = 5, _('AOKI')
        BRSKI = 6, _('BRSKI')


    class OnboardingStatus(models.IntegerChoices):
        """Onboarding status."""

        NO_ONBOARDING = 0, _('No Onboarding')
        PENDING = 1, _('Pending')
        ONBOARDED = 2, _('Onboarded')


    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default=f'New-Device', validators=[UniqueNameValidator()]
    )
    serial_number = models.CharField(_('Serial-Number'), max_length=100)
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        related_name='devices',
        blank=True,
        null=True,
        on_delete=models.PROTECT
    )

    onboarding_protocol = models.IntegerField(
        verbose_name=_('Onboarding Protocol'),
        choices=OnboardingProtocol,
        null=False,
        blank=False)
    onboarding_status = models.IntegerField(
        verbose_name=_('Onboarding Status'),
        choices=OnboardingStatus,
        blank=False,
        null=False)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)


class IssuedDomainCredentialModel(models.Model):

    issued_domain_credential_certificate = models.OneToOneField(
        CertificateModel,
        verbose_name=_('Issued Domain Credential'),
        on_delete=models.CASCADE,
        related_name='issued_domain_credential')
    device = models.ForeignKey(
        DeviceModel,
        verbose_name=_('Device'),
        on_delete=models.CASCADE,
        related_name='issued_domain_credentials'
    )
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.CASCADE,
        related_name='issued_domain_credentials')

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __str__(self) -> str:
        return f'IssuedDomainCredential(device={self.device.unique_name}, domain={self.domain.unique_name})'


class IssuedApplicationCertificateModel(models.Model):

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['device', 'common_name'],
                name='unique_active_application_certificate_category',
                condition=models.Q(is_active=True)  # Only enforce uniqueness when is_active is True
            )
        ]

    class ApplicationCertificateType(models.IntegerChoices):

        GENERIC = 0, _('Generic')
        TLS_CLIENT = 1, _('TLS-Client')
        TLS_SERVER = 2, _('TLS-Server')

    device = models.ForeignKey(
        DeviceModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    issued_application_certificate = models.ForeignKey(
        CertificateModel,
        verbose_name=_('Application Certificate'),
        on_delete=models.CASCADE)

    issued_application_certificate_type = models.IntegerField(
        verbose_name=_('Application Certificate Type'),
        choices=ApplicationCertificateType,
        null=False,
        blank=False,
    )
    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    is_active = models.BooleanField(verbose_name=_('Active'), default=True)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)