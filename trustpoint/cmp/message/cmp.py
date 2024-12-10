from __future__ import annotations

from pyasn1.codec.der import decoder, encoder
from cryptography import x509
import datetime
from pyasn1_modules.rfc4210 import PKIMessage, PKIHeader, PKIProtection, PKIBody
from pyasn1_modules.rfc4211 import CertReqMsg
import enum


class ProtectionAlgorithm(enum.Enum):

    PASSWORD_BASED_MAC = '1.2.840.113533.7.66.13'


class Popo(enum.Enum):

    RA_VERIFIED = 'raVerified'
    SIGNATURE = 'signature'
    KEY_ENCIPHERMENT = 'keyEncipherment'
    KEY_AGREEMENT = 'keyAgreement'


class PkiMessageHeader:

    _pki_header: PKIHeader

    _pvno: int
    _sender: None | str = None
    _recipient: None | str = None
    _message_time: None | datetime.datetime = None
    _protection_algorithm: ProtectionAlgorithm
    _sender_kid: None | int = None
    _recipient_kid: None | int = None
    _transaction_id: None  | bytes = None
    _sender_nonce: None | bytes = None
    _recipient_nonce: None | bytes = None

    # free_text ignored
    # general_info ignored


    def __init__(self, header: PKIHeader) -> None:
        self._pki_header = header

        pvno = int(self.pki_header['pvno'])
        if pvno not in (2, 3):
            raise ValueError('This CMP implementation only supports CMPv2 and CMPv3.')
        self._pvno = pvno

        # TODO(AlexHx8472): Sender must be equal to signer -> common name field.

        if self.pki_header['messageTime'].isValue:
            self._message_time = datetime.datetime.strptime(
                str(self.pki_header['messageTime']), '%Y%m%d%H%M%SZ')

        if not self.pki_header['protectionAlg'].isValue:
            raise ValueError(
                'This CMP implementation requires protected CMP messages and a set protectionAlg field in the header.')

        self._protection_algorithm = ProtectionAlgorithm(str(self.pki_header['protectionAlg']['algorithm']))

        # TODO(AlexHx8472): KeyIdentifier instead of int
        if not self.pki_header['senderKID'].isValue:
            self._sender_kid = None
        if not self.pki_header['recipKID'].isValue:
            self._recipient_kid = None

        if not self.pki_header['transactionID'].isValue:
            raise ValueError('TransactionID field is missing in the CMP message header.')
        self._transaction_id = self.pki_header['transactionID'].asOctets()

        if not self.pki_header['senderNonce'].isValue:
            raise ValueError('SenderNonce field is missing in the CMP message header.')
        self._sender_nonce = self.pki_header['senderNonce'].asOctets()

        if self.pki_header['recipNonce'].isValue:
            self._recipient_nonce = self.pki_header['recipNonce'].asOctets()

        if self.pki_header['freeText'].isValue:
            raise ValueError(
                'CMP message header contains the freeText field. This is not supported by this CMP implementation.')

        if self.pki_header['generalInfo'].isValue:
            raise ValueError(
                'CMP message header contains the generalInfo field. This is not supported by this CMP implementation.')



    @property
    def pki_header(self) -> PKIHeader:
        return self._pki_header

    @property
    def sender(self) -> None | str:
        return self._sender

    @property
    def recipient(self) -> None | str:
        return self._recipient

    @property
    def message_time(self) -> None | datetime.datetime:
        return self._message_time

    @property
    def protection_algorithm(self) -> ProtectionAlgorithm:
        return self._protection_algorithm

    @property
    def sender_kid(self) -> None | int:
        return self._sender_kid

    @property
    def recipient_kid(self) -> None | int:
        return self._recipient_kid



class PkiMessageProtection:

    _pki_protection: PKIProtection
    _protection_value: bytes

    def __init__(self, pki_protection: PKIProtection) -> None:
        if not pki_protection.isValue:
            raise ValueError('Protection is missing on CMP message.')
        self._pki_protection = pki_protection

        self._protection_value = pki_protection.asOctets()

    @property
    def pki_protection(self) -> PKIProtection:
        return self._pki_protection

    @property
    def protection_value(self) -> bytes:
        return self._protection_value



class PkiMessageBody:

    _pki_body: PKIBody

    def __init__(self, pki_body: PKIBody) -> None:
        if not pki_body.isValue:
            raise ValueError('Body is missing on CMP message.')
        self._pki_body = pki_body


    @property
    def pki_body(self) -> PKIBody:
        return self._pki_body


class CertRequestMessages(PkiMessageBody):

    _certificate_request_message: CertReqMsg
    # _certificate_request:

    def __init__(self, pki_body: PKIBody) -> None:
        super().__init__(pki_body)

        number_of_cert_req_messages = len(self.pki_body[0])
        if number_of_cert_req_messages < 1:
            raise ValueError('CMP message body (CertReqMessages) is missing the request.')
        if number_of_cert_req_messages > 1:
            raise ValueError('This CMP implementation only support a single CertReqMessage per request.')

        if not self.pki_body[0][0].isValue:
            raise ValueError('The CertReqMsg is emtpy.')
        self._certificate_request_message = self.pki_body[0][0]

        print(self._certificate_request_message)





# class PkiMessage:
#
#     _pki_message: PKIMessage
#     _pki_header: PkiMessageHeader
#
#     _pvno: int
#     _message_type: str
#     _number_of_message: int
#     _popo: Popo
#
#     def __init__(self, pki_message: bytes) -> None:
#         try:
#             self._pki_message, _ = decoder.decode(pki_message, asn1Spec=PKIMessage())
#         except Exception as exception:
#             raise ValueError('Failed to parse the cmp message.') from exception
#
#         self._pvno = int(self.pki_message['header']['pvno'])
#         self._message_type = self.pki_message['body'].getName()
#         self._number_of_message = len(self.pki_message['body'][0])
#
#         if self.number_of_message != 1:
#             raise ValueError('This CMP implementation only supports a single request per cmp message.')
#
#         if not self.pki_message['body'][0][0][1].isValue:
#             # TODO(AlexHx8472): CMP Lightweight required?
#             raise ValueError('Proof of Possession field is missing in CMP message. It is required.')
#         self._popo = Popo(self.pki_message['body'][0][0][1].getName())
#
#         if self.pki_message['body'][0][0][2].isValue:
#             raise ValueError('This CMP implementation does not support regInfo inf CertReqMsg.')




    #
    # @property
    # def pvno(self) -> int:
    #     return self._pvno
    #
    # @property
    # def message_type(self) -> str:
    #     return self._message_type
    #
    # @property
    # def number_of_message(self) -> int:
    #     return self._number_of_message
    #
    # @property
    # def pki_message(self) -> PKIMessage:
    #     return self._pki_message
    #
    # def pretty_print(self) -> None:
    #     print(self.pki_message.prettyPrint())
