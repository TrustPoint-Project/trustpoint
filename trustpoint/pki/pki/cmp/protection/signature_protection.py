from pyasn1_modules import rfc4210
from pyasn1.codec.der import encoder
from pyasn1.type import univ, tag
import cryptography.hazmat.primitives.hashes as hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509


class SignatureProtection:
    """
    A class to handle signature protection for PKI (Public Key Infrastructure) messages.

    Attributes:
        ca_private_key (rsa.RSAPrivateKey): The CA private key used for signing.
        client_cert (x509.Certificate): The client's X.509 certificate.
        client_public_key (rsa.RSAPublicKey): The client's public key extracted from the certificate.
    """

    def __init__(self, ca_private_key: rsa.RSAPrivateKey, authorized_clients: list):
        """
        Initializes the SignatureProtection with a CA private key and a client certificate.

        :param ca_private_key: rsa.RSAPrivateKey, the CA private key for signing
        :param authorized_clients: list, list of x509.Certificate objects which are authorized
        """
        self.ca_private_key = ca_private_key
        self.authorized_clients = authorized_clients
        self.request_protection = None
        self.response_protection = None


    def compute_signature_protection(self, header: univ.Sequence, body: univ.Sequence) -> rfc4210.PKIProtection:
        """
        Computes the signature protection for the given header and body.

        :param header: univ.Sequence, the header of the PKI message
        :param body: univ.Sequence, the body of the PKI message
        :return: rfc4210.PKIProtection, the computed signature protection
        """
        protected_part = rfc4210.ProtectedPart()

        protected_part.setComponentByName('header', header)

        protected_part.setComponentByName('infoValue', body)

        encoded_protected_part = encoder.encode(protected_part)

        signature = self.ca_private_key.sign(
            encoded_protected_part,
            padding.PKCS1v15(),
            hashes.SHA256()
        )


        self.response_protection = rfc4210.PKIProtection(univ.BitString.fromOctetString(signature)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        return self.response_protection

    def verify_signature_protection(self, pki_message: univ.Sequence) -> bool:
        """
        Verifies the signature protection of a given PKI message.

        :param pki_message: univ.Sequence, the PKI message to be verified
        :return: bool, True if the verification is successful, False otherwise
        """
        header = pki_message.getComponentByName('header')
        body = pki_message.getComponentByName('body')
        self.request_protection = pki_message.getComponentByName('protection')

        protected_part = rfc4210.ProtectedPart()
        protected_part.setComponentByName('header', header)
        protected_part.setComponentByName('infoValue', body)

        encoded_protected_part = encoder.encode(protected_part)
        signature = self.request_protection.asOctets()

        verification_status = False

        for cert in self.authorized_clients:
            authorized_pub_key = cert.public_key()
            try:
                authorized_pub_key.verify(
                    signature,
                    encoded_protected_part,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print("Verification successful: The signature of the protection is correct.")
                verification_status = True
                break
            except Exception as e:
                print(f"Verification failed: The signature of the protection is incorrect. {e}")

        return verification_status