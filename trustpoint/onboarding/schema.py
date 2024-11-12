"""Onboarding-specific Ninja Schemas"""

from ninja import Schema

class AokiInitMessageSchema(Schema):
    """Schema for the initial message sent by the client."""
    idevid: str  # PEM (?)
    client_nonce: str  # hex token


class AokiInitResponseSchema(Schema):
    """Schema for the server response to the initial message sent by the client."""
    ownership_cert: str # PEM
    server_nonce: str  # hex token
    client_nonce: str
    server_tls_cert: str  # PEM
    # + 'aoki-server-signature' in response HTTP header


class AokiFinalizationMessageSchema(Schema):
    """Schema for the finalization message sent by the client."""
    server_nonce: str
    # + 'aoki-client-signature' in response HTTP header


class AokiFinalizationResponseSchema(Schema):
    """Schema for the server response to the finalization message sent by the client."""
    otp: str
    device: str
    domain: str
    signature_suite: str
    pki_protocol: str
