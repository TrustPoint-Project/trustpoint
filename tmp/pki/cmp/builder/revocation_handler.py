from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc5280
from pyasn1.type import univ
import json

from pki.models import CertificateModel
from . import ParseHelper, BadRequest


class RevocationHandler:
    """
    A class to handle the parsing and processing of revocation requests in PKI messages.

    Attributes:
        decoded_message (Sequence): The decoded PKI message containing revocation requests.
        revocation_requests (list): List of parsed revocation requests.
    """

    def __init__(self, decoded_message: univ.Sequence, issuing_ca_object):
        """
        Initializes the RevocationHandler with a decoded PKI message.

        :param decoded_message: Sequence, the decoded PKI message containing revocation requests
        """
        self.decoded_message = decoded_message
        self.issuing_ca_object = issuing_ca_object
        self.revocation_requests = []
        self._parse_message()

    def _is_hexadecimal(self, s):
        hex_chars = set('0123456789abcdefABCDEF')
        return all(c in hex_chars for c in s)

    def _parse_message(self):
        """
        Parses the decoded PKI message to extract revocation request details.
        """
        rev_req_content = self.decoded_message.getComponentByPosition(0)

        cert_details = rev_req_content.getComponentByName('certDetails')
        serial_number = cert_details.getComponentByName('serialNumber')
        issuer = cert_details.getComponentByName('issuer')

        issuer_ca = self.issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()

        if not self._parse_issuer(issuer) == self._parse_issuer(issuer):
            raise BadRequest("Wrong issuer")

        reason_code = None
        crl_entry_details = rev_req_content.getComponentByName('crlEntryDetails')
        if crl_entry_details:
            reason_code = self.extract_reason_code(crl_entry_details)

        serial_number_hex = hex(serial_number)[2:].upper()

        # TODO: Filter the Issuing CA
        #issuer_public_bytes = issuer_ca.public_bytes(Encoding.DER)
        #issuer_public_bytes_hex = issuer_public_bytes.hex().upper()

        certificate_query = CertificateModel.objects.filter(serial_number=serial_number_hex)

        if len(certificate_query) == 0:
            raise BadRequest("Certificate not found")

        if len(certificate_query) > 1:
            raise BadRequest("Several certificates for serial number found")

        # revocation_status =  certificate_query[0].revoke(revocation_reason=reason_code)

    def _parse_issuer(self, issuer: univ.Sequence) -> str:
        """
        Parses the issuer information from the given sequence.

        :param issuer: Sequence, the ASN.1 sequence containing issuer information
        :return: str, the parsed issuer name in a readable format
        """
        rdn_sequence = issuer.getComponentByPosition(0)
        issuer_parts = []

        for rdn in rdn_sequence:
            for atav in rdn:
                type_oid = atav.getComponentByName('type')
                value = atav.getComponentByName('value')
                value_decoded, _ = decode(value, asn1Spec=rfc5280.DirectoryString())
                value_str = self._decode_directory_string(value_decoded)
                attribute_name = ParseHelper.OID_TO_NAME.get(str(type_oid), str(type_oid))
                issuer_parts.append(f"{attribute_name}={value_str}")

        return ', '.join(filter(None, issuer_parts))

    @staticmethod
    def _decode_directory_string(directory_string: rfc5280.DirectoryString) -> str:
        """
        Decodes a directory string into a readable format.

        :param directory_string: rfc5280.DirectoryString, the ASN.1 directory string to decode
        :return: str, the decoded directory string
        """
        if directory_string.getName() == "utf8String":
            return str(directory_string['utf8String'])
        elif directory_string.getName() == "printableString":
            return str(directory_string['printableString'])
        elif directory_string.getName() == "teletexString":
            return str(directory_string['teletexString'])
        elif directory_string.getName() == "bmpString":
            return str(directory_string['bmpString'])
        elif directory_string.getName() == "universalString":
            return str(directory_string['universalString'])
        else:
            return str(directory_string.getComponent())

    @staticmethod
    def extract_reason_code(crl_entry_details: univ.Sequence) -> str:
        """
        Extracts the reason code from the CRL entry details.

        :param crl_entry_details: Sequence, the ASN.1 sequence containing CRL entry details
        :return: str, the extracted reason code description
        """
        for extension in crl_entry_details:
            extn_id = extension.getComponentByName('extnID')
            if extn_id == rfc5280.id_ce_cRLReasons:
                extn_value = extension.getComponentByName('extnValue')
                reason_code, _ = decode(extn_value, asn1Spec=rfc5280.CRLReason())
                return ParseHelper.REASON_CODES.get(int(reason_code), 'unknown')
        return 'unspecified'

    def to_json(self) -> str:
        """
        Converts the parsed revocation requests to a JSON string.

        :return: str, the JSON string representation of the revocation requests
        """
        return json.dumps(self.revocation_requests, indent=4)

    def pretty_print(self):
        """
        Prints the parsed revocation requests in a pretty-printed JSON format.
        """
        print(json.dumps(self.revocation_requests, indent=4))

    def generate_response(self) -> int:
        """
        Generates a response status for the revocation request.

        :return: int, the response status code
        """
        # TODO: Not operational. Add logic to response handling
        return ParseHelper.PKI_STATUSES['accepted']
