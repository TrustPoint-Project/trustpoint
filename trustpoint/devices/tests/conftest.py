import pytest
from devices.models import DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
from devices.issuer import LocalDomainCredentialIssuer
from pki.models import DomainModel, IssuingCaModel
from pki.management.commands.base_commands import CertificateCreationCommandMixin

@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """Fixture to enable database access for all tests."""
    pass

def create_mock_models() -> dict:
    root_1, root_1_key = CertificateCreationCommandMixin.create_root_ca('Test Root CA')
    issuing_1, issuing_1_key = CertificateCreationCommandMixin.create_issuing_ca(
                                    root_1_key, 'Root CA', 'Issuing CA A')

    CertificateCreationCommandMixin.save_issuing_ca(
        issuing_ca_cert=issuing_1,
        root_ca_cert=root_1,
        private_key=issuing_1_key,
        chain=[],
        unique_name='test_local_ca')

    mock_ca = IssuingCaModel.objects.get(unique_name='test_local_ca')

    mock_domain = DomainModel(unique_name='test_domain', issuing_ca=mock_ca)
    mock_domain.save()

    mock_device = DeviceModel(
        unique_name='test_device',
        serial_number='1234567890',
        domain=mock_domain,
        onboarding_protocol=DeviceModel.OnboardingProtocol.MANUAL,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING
    )
    mock_device.save()

    credential_issuer = LocalDomainCredentialIssuer(device=mock_device, domain=mock_domain)
    mock_issued_credential = credential_issuer.issue_domain_credential()

    mock_remote_credential_download = RemoteDeviceCredentialDownloadModel(
        issued_credential_model=mock_issued_credential,
        device = mock_device
    )

    return {
        'device': mock_device,
        'domain': mock_domain,
        'ca': mock_ca,
        'issued_credential': mock_issued_credential,
        'remote_credential_download': mock_remote_credential_download
    }

@pytest.fixture
def mock_models() -> dict:
    return create_mock_models()
