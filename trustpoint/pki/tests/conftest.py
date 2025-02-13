import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# ----------------------------
# RSA Private Key Fixture
# ----------------------------

@pytest.fixture(scope="function")
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a reusable RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# ----------------------------
# EC Private Key Fixture
# ----------------------------

@pytest.fixture(scope="function")
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a reusable EC private key."""
    return ec.generate_private_key(ec.SECP256R1())
