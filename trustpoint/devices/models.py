from __future__ import annotations

import datetime
import logging
import secrets
from typing import TYPE_CHECKING

from core.serializer import CredentialSerializer
from core.validator.field import UniqueNameValidator
from core.x509 import CryptographyUtils
from cryptography import x509
from django.db import models  # type: ignore[import-untyped]
from django.utils import timezone  # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from pki.models import CertificateModel, CredentialModel, DomainModel, IssuingCaModel

if TYPE_CHECKING:
    import ipaddress

logger = logging.getLogger(__name__)


class DeviceModel(models.Model):

    def get_domain_credential_issuer(self) -> DomainCredentialIssuer:
        return DomainCredentialIssuer(device=self, domain=self.domain)

    def get_application_credential_issuer(
            self,
            credential_type: IssuedApplicationCertificateModel.ApplicationCertificateType
    ) -> TlsClientCredentialIssuer | TlsServerCredentialIssuer:
        if credential_type == IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_CLIENT:
            return self.get_tls_client_credential_issuer()
        if credential_type == IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_SERVER:
            return self.get_tls_server_credential_issuer()
        raise ValueError('Unknown issuer type')

    def get_tls_client_credential_issuer(self) -> TlsClientCredentialIssuer:
        return TlsClientCredentialIssuer(device=self, domain=self.domain)

    def get_tls_server_credential_issuer(self) -> TlsServerCredentialIssuer:
        return TlsServerCredentialIssuer(device=self, domain=self.domain)

    def __str__(self) -> str:
        return f'DeviceModel(unique_name={self.unique_name})'


    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        NO_ONBOARDING = 0, _('No Onboarding')
        MANUAL = 1, _('Manual download')
        CLI = 2, _('Device CLI')
        TP_CLIENT_PW = 3, _('Trustpoint Client')
        AOKI = 4, _('AOKI')
        BRSKI = 5, _('BRSKI')


    class OnboardingStatus(models.IntegerChoices):
        """Onboarding status."""

        NO_ONBOARDING = 0, _('No Onboarding')
        PENDING = 1, _('Pending')
        ONBOARDED = 2, _('Onboarded')


    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default='New-Device', validators=[UniqueNameValidator()]
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
        on_delete=models.PROTECT,
        related_name='issued_domain_credential')
    device = models.ForeignKey(
        DeviceModel,
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='issued_domain_credentials')
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.PROTECT,
        related_name='issued_domain_credentials')
    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        verbose_name=_('Issuing CA'),
        on_delete=models.PROTECT,
        related_name='issued_domain_credentials')

    # This is only set if the credential, including the key pair, was generated on the Trustpoint itself.
    credential = models.OneToOneField(
        CredentialModel,
        verbose_name=_('Credential'),
        on_delete=models.PROTECT,
        related_name='issued_domain_credential',
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __str__(self) -> str:
        return f'IssuedDomainCredential(device={self.device.unique_name}, domain={self.domain.unique_name})'


class IssuedApplicationCertificateModel(models.Model):

    class ApplicationCertificateType(models.IntegerChoices):

        GENERIC = 0, _('Generic')
        TLS_CLIENT = 1, _('TLS-Client')
        TLS_SERVER = 2, _('TLS-Server')

    issued_application_certificate = models.ForeignKey(
        CertificateModel,
        verbose_name=_('Application Certificate'),
        on_delete=models.CASCADE)
    device = models.ForeignKey(
        DeviceModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        verbose_name=_('Issuing CA'),
        on_delete=models.PROTECT,
        related_name='issued_application_credentials')
    issued_application_certificate_type = models.IntegerField(
        verbose_name=_('Application Certificate Type'),
        choices=ApplicationCertificateType,
        null=False,
        blank=False)

    # This is only set if the credential, including the key pair, was generated on the Trustpoint itself.
    credential = models.OneToOneField(
        CredentialModel,
        verbose_name=_('Credential'),
        on_delete=models.PROTECT,
        related_name='issued_application_credential',
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __str__(self) -> str:
        return f'IssuedApplicationCredential(device={self.device.unique_name}, domain={self.domain.unique_name})'


class DomainCredentialIssuer:

    _common_name: str = 'Trustpoint Domain Credential'
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_domain_credential_model: None | IssuedDomainCredentialModel = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        return self._device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @property
    def serial_number(self) -> str:
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        return self.domain.unique_name

    @property
    def common_name(self) -> str:
        return self._common_name

    @property
    def credential(self) -> None | CredentialSerializer:
        return self._credential

    @property
    def credential_model(self) -> None | CredentialModel:
        return self._credential_model

    @property
    def issued_domain_credential_model(self) -> None | IssuedDomainCredentialModel:
        return self._issued_domain_credential_model

    def get_fixed_values(self) -> dict[str, str]:
        return {
            'common_name': self.common_name,
            'domain_component': self.domain_component,
            'serial_number': self.serial_number
        }

    def issue_domain_credential(self):
        domain_credential_private_key = CryptographyUtils.generate_private_key(domain=self.domain)
        hash_algorithm = CryptographyUtils.get_hash_algorithm_from_domain(domain=self.domain)
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
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

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(domain_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        self._credential = CredentialSerializer(
            (
                domain_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

    def save(self) -> None:
        self._credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=self.credential,
            credential_type=CredentialModel.CredentialTypeChoice.DOMAIN_CREDENTIAL)


        issued_domain_credential = IssuedDomainCredentialModel(
            issued_domain_credential_certificate=self.credential_model.certificate,
            device=self.device,
            domain=self.domain,
            issuing_ca=self.domain.issuing_ca,
            credential=self.credential_model
        )
        issued_domain_credential.save()
        self._issued_domain_credential_model = issued_domain_credential


class TlsClientCredentialIssuer:

    _pseudonym: str = 'Trustpoint Application Credential - TLS Client'
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_application_credential_model: None | IssuedApplicationCertificateModel = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        return self._device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @property
    def serial_number(self) -> str:
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        return self.domain.unique_name

    @property
    def pseudonym(self) -> str:
        return self._pseudonym

    @property
    def credential(self) -> None | CredentialSerializer:
        return self._credential

    @property
    def credential_model(self) -> None | CredentialModel:
        return self._credential_model

    @property
    def issued_application_credential_model(self) -> None | IssuedApplicationCertificateModel:
        return self._issued_application_credential_model

    def get_fixed_values(self) -> dict[str, str]:
        return {
            'pseudonym': self.pseudonym,
            'domain_component': self.domain_component,
            'serial_number': self.serial_number
        }

    def issue_tls_client_credential(self, common_name: str, validity_days: int) -> None:
        application_credential_private_key = CryptographyUtils.generate_private_key(domain=self.domain)
        hash_algorithm = CryptographyUtils.get_hash_algorithm_from_domain(domain=self.domain)
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.NameOID.PSEUDONYM, self.pseudonym),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number)
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
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
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
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(application_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        self._credential = CredentialSerializer(
            (
                application_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

    def save(self) -> None:

        self._credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=self.credential,
            credential_type=CredentialModel.CredentialTypeChoice.APPLICATION_CREDENTIAL)

        issued_application_credential = IssuedApplicationCertificateModel(
            issued_application_certificate=self.credential_model.certificate,
            device=self.device,
            domain=self.domain,
            issuing_ca=self.domain.issuing_ca,
            issued_application_certificate_type=IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_CLIENT,
            credential=self.credential_model
        )
        issued_application_credential.save()
        self._issued_application_credential_model = issued_application_credential


class TlsServerCredentialIssuer:

    _pseudonym: str = 'Trustpoint Application Credential - TLS Server'
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_application_credential_model: None | IssuedApplicationCertificateModel = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        return self._device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @property
    def serial_number(self) -> str:
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        return self.domain.unique_name

    @property
    def pseudonym(self) -> str:
        return self._pseudonym

    @property
    def credential(self) -> None | CredentialSerializer:
        return self._credential

    @property
    def credential_model(self) -> None | CredentialModel:
        return self._credential_model

    @property
    def issued_application_credential_model(self) -> None | IssuedApplicationCertificateModel:
        return self._issued_application_credential_model

    def get_fixed_values(self) -> dict[str, str]:
        return {
            'pseudonym': self.pseudonym,
            'domain_component': self.domain_component,
            'serial_number': self.serial_number
        }

    def issue_tls_server_credential(
            self,
            common_name: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            validity_days: int) -> None:
        application_credential_private_key = CryptographyUtils.generate_private_key(domain=self.domain)
        hash_algorithm = CryptographyUtils.get_hash_algorithm_from_domain(domain=self.domain)
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.NameOID.PSEUDONYM, self.pseudonym),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number)
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
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
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
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(application_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )

        ipv4_addresses = [x509.IPAddress(ipv4_address) for ipv4_address in ipv4_addresses]
        ipv6_addresses = [x509.IPAddress(ipv6_address) for ipv6_address in ipv6_addresses]
        domain_names = [x509.DNSName(domain_name) for domain_name in domain_names]

        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(
                ipv4_addresses + ipv6_addresses + domain_names
            ),
            critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        self._credential = CredentialSerializer(
            (
                application_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

    def save(self) -> None:

        self._credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=self.credential,
            credential_type=CredentialModel.CredentialTypeChoice.APPLICATION_CREDENTIAL)

        issued_application_credential = IssuedApplicationCertificateModel(
            issued_application_certificate=self.credential_model.certificate,
            device=self.device,
            domain=self.domain,
            issuing_ca=self.domain.issuing_ca,
            issued_application_certificate_type=IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_SERVER,
            credential=self.credential_model
        )
        issued_application_credential.save()
        self._issued_application_credential_model = issued_application_credential


class RemoteDeviceCredentialDownloadModel(models.Model):
    BROWSER_MAX_OTP_ATTEMPTS = 3
    TOKEN_VALIDITY = datetime.timedelta(minutes=3)

    issued_credential_model = models.OneToOneField(IssuedDomainCredentialModel, on_delete=models.CASCADE)
    otp = models.CharField(_('OTP'), max_length=32, null=True)
    device = models.ForeignKey(DeviceModel, on_delete=models.CASCADE)
    attempts = models.IntegerField(_('Attempts'), default=0)
    download_token = models.CharField(_('Download Token'), max_length=64, null=True)
    token_created_at = models.DateTimeField(_('Token Created'), null=True)

    def save(self, *args: dict, **kwargs: dict) -> None:
        if not self.otp:
            self.otp = secrets.token_urlsafe(8)
        super().save(*args, **kwargs)

    def get_otp_display(self) -> str:
        if not self.otp or self.otp == '-':
            return 'OTP no longer valid'
        return f'{self.issued_credential_model.id}.{self.otp}'

    def check_otp(self, otp: str) -> bool:
        if not self.otp or self.otp == '-':
            return False
        matches = otp == self.otp
        if not matches:
            self.attempts += 1
            logger.warning(
                f'Incorrect OTP attempt {self.attempts} for browser credential download for device {self.device.unique_name} (credential id={self.issued_credential_model.id})'
            )
            if self.attempts >= self.BROWSER_MAX_OTP_ATTEMPTS:
                self.delete()
                logger.warning('Too many incorrect OTP attempts. Download invalidated.')
            else:
                self.save()
            return False

        logger.info(
            f'Correct OTP entered for browser credential download for device {self.device.unique_name} (credential id={self.issued_credential_model.id})'
        )
        self.otp = '-'
        self.download_token = secrets.token_urlsafe(32)
        self.token_created_at = timezone.now()
        self.save()
        return True

    def check_token(self, token: str) -> bool:
        if not self.download_token or not self.token_created_at:
            return False
        if timezone.now() - self.token_created_at > self.TOKEN_VALIDITY:
            self.delete()
            return False

        return token == self.download_token
