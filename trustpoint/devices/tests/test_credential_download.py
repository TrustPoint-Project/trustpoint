import pytest
import secrets

def test_otp_generation(mock_models):
    """Test that a valid OTP is generated on save."""
    remote_credential_download_model = mock_models['remote_credential_download']
    assert remote_credential_download_model.otp == ''
    remote_credential_download_model.save()
    assert len(remote_credential_download_model.otp) == len(secrets.token_urlsafe(8))


def test_token_invalidation(mock_models):
    """Test that a download token is no longer valid after the token validity period."""

def test_otp_use_once():
    """Test that an OTP can only be used once."""

def test_otp_max_attempts():
    """Test that the OTP is invalidated after too many incorrect attempts."""
    pass # NYI
