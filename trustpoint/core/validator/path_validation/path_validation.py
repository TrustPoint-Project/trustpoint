from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from datetime import datetime, timezone
from typing import List, Tuple, Union


class CertificatePathValidator:
    """CertificatePathValidator validates a given certificate against a chain of intermediates and trusted CAs."""

    def __init__(self, trusted_certs: List[x509.Certificate], intermediates: List[x509.Certificate],
                 cert_to_validate: x509.Certificate):
        """Initializes the CertificatePathValidator with the given certificates.

        Args:
            trusted_certs (List[x509.Certificate]): A list of trusted root certificates.
            intermediates (List[x509.Certificate]): A list of intermediate certificates.
            cert_to_validate (x509.Certificate): The certificate that needs validation.
        """
        if not trusted_certs:
            raise ValueError("A list of trusted certificates is required.")

        self.trusted_certs = trusted_certs
        self.intermediates = intermediates
        self.cert_to_validate = cert_to_validate
        self.chain = []

    def _build_chain(self) -> Tuple[bool, Union[str, None]]:
        """Constructs a valid certificate chain from the certificate to validate up to a trusted certificate.

        Returns:
            - (True, None) if the chain is successfully built.
            - (False, error_message) if the chain cannot be built.
        """
        try:
            chain = [self.cert_to_validate]
            remaining_certs = {cert.subject: cert for cert in self.intermediates}

            while True:
                last_cert = chain[-1]

                if any(last_cert.fingerprint(SHA256()) == trusted.fingerprint(SHA256()) for trusted in self.trusted_certs):
                    self.chain = chain
                    return True, None

                if last_cert.issuer == last_cert.subject:
                    if any(last_cert.fingerprint(SHA256()) == trusted.fingerprint(SHA256()) for trusted in self.trusted_certs):
                        self.chain = chain
                        return True, None
                    return False, f"Self-signed certificate {last_cert.subject.rfc4514_string()} is not trusted."

                issuer_cert = remaining_certs.get(last_cert.issuer)

                if issuer_cert is None:
                    for trusted in self.trusted_certs:
                        if last_cert.issuer == trusted.subject:
                            issuer_cert = trusted
                            break

                if issuer_cert is None:
                    return False, f"No valid issuer found for: {last_cert.subject.rfc4514_string()}"

                chain.append(issuer_cert)

        except Exception as e:
            return False, f"Unexpected error during chain construction: {str(e)}"

    def validate(self) -> Tuple[bool, Union[str, None]]:
        """Validates the certificate against the built chain.

        Returns:
          - (True, None) if validation is successful.
          - (False, error_message) if validation fails.
        """
        success, error_message = self._build_chain()
        if not success:
            return False, error_message

        try:
            self._validate_time_constraints()
            self._validate_signatures()
            return True, None
        except Exception as e:
            return False, str(e)

    def _validate_time_constraints(self):
        """Ensures all certificates in the chain are currently valid."""
        current_time = datetime.now(timezone.utc)
        for cert in self.chain:
            if cert.not_valid_before_utc > current_time or cert.not_valid_after_utc < current_time:
                raise ValueError(f"Certificate {cert.subject.rfc4514_string()} is not valid at the current time.")

    def _validate_signatures(self):
        """Verifies that each certificate is correctly signed by the next in the chain."""
        for i in range(len(self.chain) - 1):
            cert = self.chain[i]
            issuer_cert = self.chain[i + 1]

            try:
                public_key = issuer_cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm),
                    )
                else:
                    raise ValueError(f"Unsupported public key type for {issuer_cert.subject.rfc4514_string()}")

            except Exception as e:
                raise ValueError(f"Signature verification failed for {cert.subject.rfc4514_string()}: {str(e)}")

    def get_chain(self) -> List[x509.Certificate]:
        """Returns the certificate chain as a list of x509.Certificate objects."""
        return self.chain
