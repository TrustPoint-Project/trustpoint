import hmac
import hashlib
from pyasn1.type import univ, tag
from pyasn1_modules import rfc4210
from pyasn1.codec.der import decoder, encoder

from . import ParseHelper


class PBMProtection:
    """
    A class to handle PBM (Password-Based Message Authentication Code) protection for
    PKI (Public Key Infrastructure) messages.

    Attributes:
        shared_secret (bytes): The shared secret used for key derivation and message protection.
    """

    def __init__(self, shared_secret: bytes):
        """
        Initializes the PBMProtection with a shared secret.

        :param shared_secret: bytes, the shared secret for PBM protection
        """
        self.shared_secret = shared_secret

    def extract_pbm_parameters(self, header: univ.Sequence) -> rfc4210.PBMParameter:
        """
        Extracts the PBM parameters from the given header.

        :param header: univ.Sequence, the header containing the PBM parameters
        :return: rfc4210.PBMParameter, the extracted PBM parameters
        """
        protectionAlg = header.getComponentByName('protectionAlg')

        parameters = protectionAlg.getComponentByName('parameters')
        # if parameters.isNoValue():
        #     raise ValueError("parameters are missing in protectionAlg")
        decoded_data, _ = decoder.decode(parameters, asn1Spec=rfc4210.PBMParameter())
        return decoded_data

    def compute_derived_key(self, pbm_params: rfc4210.PBMParameter) -> bytes:
        """
        Computes the derived key using the PBM parameters.

        :param pbm_params: rfc4210.PBMParameter, the PBM parameters for key derivation
        :return: bytes, the derived key
        :raises ValueError: If the OWF algorithm is unsupported
        """
        salt = pbm_params.getComponentByName('salt').asOctets()
        owf = pbm_params.getComponentByName('owf').getComponentByName('algorithm')
        iteration_count = int(pbm_params.getComponentByName('iterationCount'))

        if str(owf) not in ParseHelper.oid_to_hash:
            raise ValueError("Unsupported OWF algorithm")

        owf_hash_func = ParseHelper.oid_to_hash[str(owf)]

        derived_key = hashlib.pbkdf2_hmac(
            owf_hash_func().name,
            self.shared_secret,
            salt,
            iteration_count
        )

        return derived_key

    def pbm_parameter_derived_key(self, shared_secret: bytes, pbm_params: rfc4210.PBMParameter, mac_key_len: int) -> bytes:
        """
        Derives a key from PBM parameters and a shared secret.

        :param shared_secret: bytes, the shared secret for key derivation
        :param pbm_params: rfc4210.PBMParameter, the PBM parameters for key derivation
        :param mac_key_len: int, the length of the MAC key
        :return: bytes, the derived key
        :raises ValueError: If the salt is not of type OctetString or if the OWF algorithm is unsupported
        """
        salt = pbm_params.getComponentByName('salt')

        if not isinstance(salt, univ.OctetString):
            raise ValueError("Salt is not of type OctetString")

        salt_octets = salt.asOctets()

        owf = pbm_params.getComponentByName('owf').getComponentByName('algorithm')
        iteration_count = int(pbm_params.getComponentByName('iterationCount'))

        if str(owf) not in ParseHelper.oid_to_hash:
            raise ValueError("Unsupported OWF algorithm")

        owf_hash_func = ParseHelper.oid_to_hash[str(owf)]

        def iterative_owf(data, iterations):
            for _ in range(iterations):
                data = owf_hash_func(data).digest()
            return data

        salted_secret = shared_secret + salt_octets
        basekey = iterative_owf(salted_secret, iteration_count)

        return basekey

    def compute_pbm_protection(self, header: univ.Sequence, body: univ.Sequence, pbm_params: rfc4210.PBMParameter) -> rfc4210.PKIProtection:
        """
        Computes the PBM protection for the given header and body.

        :param header: univ.Sequence, the header of the PKI message
        :param body: univ.Sequence, the body of the PKI message
        :param pbm_params: rfc4210.PBMParameter, the PBM parameters for computing the protection
        :return: rfc4210.PKIProtection, the computed PBM protection
        :raises ValueError: If the MAC algorithm is unsupported
        """
        derived_key = self.pbm_parameter_derived_key(self.shared_secret, pbm_params, 256)

        mac_algorithm = pbm_params.getComponentByName('mac').getComponentByName('algorithm')
        if str(mac_algorithm) not in ParseHelper.oid_to_hash:
            raise ValueError("Unsupported MAC algorithm")

        mac_hash_func = ParseHelper.oid_to_hash[str(mac_algorithm)]

        protected_part = rfc4210.ProtectedPart()

        protected_part.setComponentByName('header', header)
        protected_part.setComponentByName('infoValue', body)

        encoded_protected_part = encoder.encode(protected_part)

        mac_value = hmac.new(derived_key, encoded_protected_part, mac_hash_func).digest()

        protection_int = int.from_bytes(mac_value, byteorder='big')

        protection_binary_str = bin(protection_int)[2:]

        protection = rfc4210.PKIProtection(univ.BitString(protection_binary_str)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        return protection

    def verify_pbm_protection(self, pki_message: univ.Sequence, shared_secret: bytes) -> bool:
        """
        Verifies the PBM protection of a given PKI message.

        :param pki_message: univ.Sequence, the PKI message to be verified
        :param shared_secret: bytes, the shared secret for verification
        :return: bool, True if the verification is successful, False otherwise
        :raises ValueError: If the MAC algorithm is unsupported
        """
        header = pki_message.getComponentByName('header')
        body = pki_message.getComponentByName('body')
        protection = pki_message.getComponentByName('protection')

        pbm_params = self.extract_pbm_parameters(header)

        key = self.pbm_parameter_derived_key(shared_secret, pbm_params, 256)


        mac_algorithm = pbm_params.getComponentByName('mac').getComponentByName('algorithm')
        if str(mac_algorithm) not in ParseHelper.oid_to_hash:
            raise ValueError("Unsupported MAC algorithm")

        mac_hash_func = ParseHelper.oid_to_hash[str(mac_algorithm)]

        protected_part = rfc4210.ProtectedPart()

        protected_part.setComponentByName('header', header)
        protected_part.setComponentByName('infoValue', body)

        encoded_protected_part = encoder.encode(protected_part)

        mac_value = hmac.new(key, encoded_protected_part, mac_hash_func).digest()

        if hmac.compare_digest(protection.asOctets().hex(), mac_value.hex()):
            print("Verification successful: The shared secret of the protection is correct.")
            return True
        else:
            print("Verification failed: The shared secret  of the protection is incorrect.")
            return False
