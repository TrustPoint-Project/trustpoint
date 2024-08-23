from cryptography.x509 import Certificate
from pyasn1_modules import rfc4210
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.type import univ
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from .. import (
    PBMProtection, SignatureProtection, ParseHelper, BadRequest, UnacceptedPolicy, NotAuthorized
)

class RFC4210Protection:
    """
    A class to handle protection mechanisms for RFC 4210 PKI messages, supporting both
    PBM (Password-Based Message Authentication Code) and signature-based protection.

    Attributes:
        _pki_message (Sequence): The PKI message to be protected or validated.
        _ca_cert (x509.Certificate): The CA certificate.
        _shared_secret (bytes): The shared secret for PBM protection.
        _ca_private_key (rsa.RSAPrivateKey): The CA private key for signature protection.
        _client_cert (x509.Certificate): The client certificate for signature protection.
        _pbm_based_protection (bool): Indicates if PBM protection is used.
        _signature_based_protection (bool): Indicates if signature protection is used.
        _protection_type (str): The type of protection used.
        _protection_mode (str): The protection mode. Signature or PBM
        _protection_alg (ObjectIdentifier): The protection algorithm used.
        _valid_protection (bool): Indicates if the protection is valid.
        _algorithm_oid (str): The OID of the protection algorithm.
    """
    def __init__(self, pki_message: univ.Sequence, ca_cert: x509.Certificate):
        """
        Initializes the RFC4210Protection with a PKI message and a CA certificate.

        :param pki_message: Sequence, the PKI message to be protected or validated
        :param ca_cert: x509.Certificate, the PEM-encoded CA certificate
        """
        self._pki_message = pki_message
        self._ca_cert = ca_cert
        self._shared_secret = None
        self._ca_private_key = None
        self._authorized_clients = None
        self._pbm_based_protection = False
        self._signature_based_protection = False
        self._protection_type = None
        self._protection_mode = None
        self._protection_alg = None
        self._valid_protection = None
        self._algorithm_oid = None

    def signature_protection(self, ca_private_key: rsa.RSAPrivateKey = None, authorized_clients: list = None):
        """
        Configures the class to use signature-based protection.

        :param ca_private_key: rsa.RSAPrivateKey, the CA private key for signing
        :param client_cert: str, the PEM-encoded client certificate
        """
        self._ca_private_key = ca_private_key
        self._authorized_clients = authorized_clients
        self._signature_based_protection = True
        self._parse_header()


    def pbm_protection(self, shared_secret: bytes = None):
        """
        Configures the class to use PBM-based protection.

        :param shared_secret: bytes, the shared secret for PBM protection
        """
        self._shared_secret = shared_secret
        self._pbm_based_protection = True
        self._parse_header()


    def _parse_header(self):
        """
        Parses the header of the PKI message to determine the protection algorithm and type.
        """
        header = self._pki_message.getComponentByName('header')
        self._protection_alg = header.getComponentByName('protectionAlg')


        self._algorithm_oid = self._protection_alg.getComponentByName('algorithm').prettyPrint()
        self._protection_type = ParseHelper.oid_to_protection_type.get(self._algorithm_oid, "Unknown Protection Type")
        if self._protection_type == 'Password-based MAC':
            if not self._pbm_based_protection:
                raise UnacceptedPolicy("PBM based protection is not allowed")
            if not self._shared_secret:
                raise BadRequest("Shared secret is required for PBM protection")
        elif 'RSA' in self._protection_type or 'ECDSA' in self._protection_type:
            if not self._signature_based_protection:
                raise UnacceptedPolicy("Signature based protection is not allowed")
            if not self._ca_private_key:
                raise BadRequest("Private key is required for signature protection")
            if not self._authorized_clients:
                raise BadRequest("Client cert is required for signature protection")
        else:
            raise UnacceptedPolicy(f"Protection type '{self._protection_type}' is not supported")


    def compute_protection(self, header: univ.Sequence, body: univ.Sequence) -> rfc4210.PKIProtection:
        """
        Computes the protection for the given header and body based on the configured protection type.

        :param header: Sequence, the header of the PKI message
        :param body: Sequence, the body of the PKI message
        :return: rfc4210.PKIProtection, the computed protection
        :raises UnacceptedPolicy: If the protection type is not supported
        """
        if self._protection_type == 'Password-based MAC':
            pbm_protection = PBMProtection(self._shared_secret)
            protection = pbm_protection.compute_pbm_protection(header, body, pbm_protection.extract_pbm_parameters(header))
            return protection
        elif 'RSA' in self._protection_type or 'ECDSA' in self._protection_type:
            signature_protection = SignatureProtection(self._ca_private_key, self._authorized_clients)
            protection = signature_protection.compute_signature_protection(header, body)
            return protection
        else:
            raise UnacceptedPolicy("Protection not supported")

    def validate_protection(self):
        """
        Validates the protection of the PKI message based on the configured protection type.

        :raises NotAuthorized: If the protection is invalid
        :raises UnacceptedPolicy: If the protection type is not supported
        """

        if self._protection_type == 'Password-based MAC':
            pbm_protection = PBMProtection(self._shared_secret)
            pbm_verification = pbm_protection.verify_pbm_protection(self._pki_message, self._shared_secret)
            if not pbm_verification:
                raise NotAuthorized("Invalid PBM protection")
            else:
                self._valid_protection = True
        elif 'RSA' in self._protection_type or 'ECDSA' in self._protection_type:
            signature_protection = SignatureProtection(self._ca_private_key, self._authorized_clients)
            signature_verification = signature_protection.verify_signature_protection(self._pki_message)
            if not signature_verification:
                raise NotAuthorized("Invalid signature protection")
            else:
                self._valid_protection = True
        else:
            raise UnacceptedPolicy("Protection not supported")

    @property
    def protection_type(self) -> str:
        """Returns the type of protection used."""
        return self._protection_type

    @property
    def protection_alg(self) -> ObjectIdentifier:
        """Returns the protection algorithm used."""
        return self._protection_alg

    @property
    def valid_protection(self) -> bool:
        """Returns whether the protection is valid."""
        return self._valid_protection

    @property
    def signature_based_protection(self) -> bool:
        """Returns whether signature-based protection is used."""
        return self._signature_based_protection

    @property
    def pbm_based_protection(self) -> bool:
        """Returns whether PBM-based protection is used."""
        return self._pbm_based_protection

    @property
    def shared_secret(self) -> bytes:
        """Returns the shared secret used for PBM protection."""
        return self._shared_secret

    @property
    def ca_private_key(self) -> rsa.RSAPrivateKey:
        """Returns the CA private key used for signature protection."""
        return self._ca_private_key

    @property
    def ca_cert(self) -> Certificate:
        """Returns the CA certificate."""
        return self._ca_cert

    @property
    def authorized_clients(self) -> str:
        """Returns the authorized_clients for signature protection."""
        return self._authorized_clients

    @property
    def algorithm_oid(self) -> str:
        """Returns the OID of the protection algorithm."""
        return self._algorithm_oid

    @property
    def protection_mode(self) -> str:
        """Returns the protection mode (signature or PBM)."""
        return self._protection_mode

    def prettyPrint(self) -> str:
        """
        Returns a string representation of the current state of the RFC4210Protection instance.

        :return: str, formatted string representing the current state
        """
        return (
            f"RFC4210Protection(\n"
            f"  pbm_based_protection        ={self._pbm_based_protection},\n"
            f"  signature_based_protection  ={self._signature_based_protection},\n"
            f"  protection_type             ={self._protection_type},\n"
            f"  algorithm_oid               ={self._algorithm_oid},\n"
            f"  valid_protection            ={self._valid_protection}\n"
            f")"
        )