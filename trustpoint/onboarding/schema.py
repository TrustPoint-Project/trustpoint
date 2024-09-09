"""Onboarding-specific Ninja Schemas"""

from ninja import Schema

class TokiInitMessageSchema(Schema):
    """Schema for the initial message sent by the client."""
    idevid: str  # PEM (?)
    client_nonce: str  # hex token


class TokiInitResponseSchema(Schema):
    """Schema for the server response to the initial message sent by the client."""
    ownership_cert: str # PEM
    server_nonce: str  # hex token
    client_nonce: str
    server_tls_cert: str  # PEM
    # + 'toki-server-signature' in response HTTP header

class TokiFinalizationMessageSchema(Schema):
    """Schema for the finalization message sent by the client."""
    # (empty)
    # + 'toki-client-signature' in response HTTP header


class TokiFinalizationResponseSchema(Schema):
    """Schema for the server response to the finalization message sent by the client."""
    otp: str
    salt: str
    url_ext: str