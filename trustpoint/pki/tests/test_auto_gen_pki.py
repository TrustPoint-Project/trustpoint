"""Tests for the auto-generated PKI."""

import pytest
from devices.issuer import LocalDomainCredentialIssuer
from devices.models import DeviceModel

from pki.auto_gen_pki import AutoGenPki
from pki.models import CertificateModel, DomainModel, IssuingCaModel
from pki.util.keys import AutoGenPkiKeyAlgorithm


def test_auto_gen_pki() -> None:
    """Test that the auto-generated PKI can be correctly enabled, used and disabled."""
    # Check that the auto-generated PKI is disabled by default
    assert AutoGenPki.get_auto_gen_pki() is None

    # Enable the auto-generated PKI
    AutoGenPki.enable_auto_gen_pki(AutoGenPkiKeyAlgorithm('SECP256R1SHA256'))

    # Check that the auto-generated PKI is enabled
    issuing_ca = AutoGenPki.get_auto_gen_pki()
    assert issuing_ca is not None

    # Use the auto-generated PKI domain to issue a domain credential to a new device
    try:
        domain = DomainModel.objects.get(unique_name='AutoGenPKI')
    except DomainModel.DoesNotExist:
        pytest.fail('Auto-generated PKI domain was not created')
    test_device = DeviceModel(
        unique_name='test_device',
        serial_number='1234567890',
        domain=domain,
        onboarding_protocol=DeviceModel.OnboardingProtocol.MANUAL,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING
    )
    test_device.save()
    credential_issuer = LocalDomainCredentialIssuer(device=test_device, domain=domain)
    issued_credential = credential_issuer.issue_domain_credential()

    # Disable the auto-generated PKI
    AutoGenPki.disable_auto_gen_pki()

    # Check that the issued credential has been revoked
    assert issued_credential.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED

    # Check that the issuing CA has been revoked and set as inactive
    issuing_ca = IssuingCaModel.objects.get(pk=issuing_ca.pk)  # reload from DB
    assert issuing_ca.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED
    assert not issuing_ca.is_active

    # Check that the auto-generated PKI is disabled
    assert AutoGenPki.get_auto_gen_pki() is None

    # Check that the domain has been set as inactive
    domain = DomainModel.objects.get(unique_name='AutoGenPKI')
    assert not domain.is_active
