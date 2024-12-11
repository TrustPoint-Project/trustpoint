from __future__ import annotations

from pyasn1.codec.der import decoder, encoder


from cryptography import x509
from cryptography.x509.name import _ASN1Type as X509_Asn1Type
import datetime
from pyasn1_modules import rfc2459, rfc4210
from cmp.message.protection_alg import ProtectionAlgorithmParser, ProtectionAlgorithm, PasswordBasedMacProtection
# from pyasn1_modules.rfc2459 import GeneralName as PyAsn1GeneralName
# from pyasn1_modules.rfc2459 import Name as PyAsn1Name
# from pyasn1_modules.rfc4210 import PKIMessage, PKIHeader, PKIProtection, PKIBody, PBMParameter
# from pyasn1_modules.rfc4211 import CertReqMsg, CertRequest, CertTemplate
from pyasn1.type.char import (
    UTF8String,
    NumericString,
    PrintableString,
    T61String,
    IA5String,
    VisibleString,
    UniversalString,
    BMPString
)
from pyasn1.type.univ import BitString, OctetString
from pyasn1.type.useful import UTCTime, GeneralizedTime
import enum


class PkiMessageType(enum.Enum):

    IR = 'ir'


class GeneralNameType(enum.Enum):

    RFC822_NAME = 'rfc822Name'
    DNS_NAME = 'dNSName'
    DIRECTORY_NAME = 'directoryName'
    UNIFORM_RESOURCE_IDENTIFIER = 'uniformResourceIdentifier'
    IP_ADDRESS = 'iPAddress'
    REGISTERED_ID = 'registeredID'
    OTHER_NAME = 'otherName'





class Popo(enum.Enum):

    RA_VERIFIED = 'raVerified'
    SIGNATURE = 'signature'
    KEY_ENCIPHERMENT = 'keyEncipherment'
    KEY_AGREEMENT = 'keyAgreement'


class NameParser:

    @classmethod
    def parse_general_name(cls, general_name: rfc2459.GeneralName) -> x509.GeneralName:
        general_name_type = GeneralNameType(general_name.getName())
        if  general_name_type == GeneralNameType.DIRECTORY_NAME:
            return x509.DirectoryName(cls.parse_name(general_name[GeneralNameType.DIRECTORY_NAME.value]))
        raise ValueError('Currently only supporting DirectoryName as GeneralName.')

    @staticmethod
    def parse_name(name: rfc2459.Name) -> x509.Name:
        rdns_sequence = name[0]
        if rdns_sequence.isValue:
            crypto_rdns_sequence: list[x509.RelativeDistinguishedName] = []
            for rdns in rdns_sequence:
                if len(rdns) < 1:
                    raise ValueError('Found empty RDN in the subject field of the certTemplate.')
                if len(rdns) > 1:
                    raise ValueError('This CMP implementation does not support multi-valued RDNs.')

                attribute_type_and_value = rdns[0]
                if not attribute_type_and_value.isValue or \
                        not attribute_type_and_value['type'].isValue or \
                        not attribute_type_and_value['value'].isValue:
                    raise ValueError('Found empty RDN in the subject field of the certTemplate.')

                attribute_type = attribute_type_and_value['type']
                crypto_oid = x509.ObjectIdentifier(str(attribute_type))

                attribute_value = attribute_type_and_value['value']
                decoded_attribute_value, _ = decoder.decode(attribute_value)

                if isinstance(decoded_attribute_value, UTF8String):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value))
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, NumericString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.NumericString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, PrintableString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.PrintableString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, T61String):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.T61String)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, IA5String):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.IA5String)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, VisibleString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.VisibleString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, UniversalString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.UniversalString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, BMPString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.BMPString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, BitString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                bytes(decoded_attribute_value),
                                _type=X509_Asn1Type.BitString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, OctetString):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.OctetString)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, UTCTime):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.UTCTime)
                        ]
                    ))
                    continue

                if isinstance(decoded_attribute_value, GeneralizedTime):
                    crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
                        [
                            x509.NameAttribute(
                                crypto_oid,
                                str(decoded_attribute_value),
                                _type=X509_Asn1Type.GeneralizedTime)
                        ]
                    ))
                    continue

                raise ValueError(
                    f'Found NameAttribute in an RDN with unknown value type: {type(decoded_attribute_value)}.')

            return x509.Name(crypto_rdns_sequence)




class PkiMessageHeader:

    _pki_header: rfc4210.PKIHeader

    _pvno: int
    _sender_kid: None | int = None
    _sender: x509.GeneralName
    _recipient_kid: None | int = None
    _recipient: x509.GeneralName
    _message_time: None | datetime.datetime = None
    _protection_algorithm: ProtectionAlgorithm
    _transaction_id: None  | bytes = None
    _sender_nonce: None | bytes = None
    _recipient_nonce: None | bytes = None
    _free_text: list[str]
    _general_info: None | str = None

    def __init__(self, header: rfc4210.PKIHeader) -> None:
        self._pki_header = header
        print(header.prettyPrint())

        pvno = int(self.pki_header['pvno'])
        if pvno not in (2, 3):
            raise ValueError('This CMP implementation only supports CMPv2 and CMPv3.')
        self._pvno = pvno

        self._sender = NameParser.parse_general_name(header['sender'])

        self._recipient = NameParser.parse_general_name(header['recipient'])

        if self.pki_header['messageTime'].isValue:
            self._message_time = datetime.datetime.strptime(
                str(self.pki_header['messageTime']), '%Y%m%d%H%M%SZ')

        if not self.pki_header['protectionAlg'].isValue:
            raise ValueError(
                'This CMP implementation requires protected CMP messages and a set protectionAlg field in the header.')
        self._protection_algorithm = ProtectionAlgorithmParser.parse_protection_algorithm(header['protectionAlg'])

        # TODO(AlexHx8472): Currently not supporting any KID fields
        # unclear of the structure -> RFC 2459 : Octetstring,
        # however RFC4210 and RFC9483 also allow common name / directory name

        # CMP lightweight requires this for mac and signature based protection, however the OSSL CMP client leaves
        # it blank for mac based protection.
        if not self.pki_header['senderKID'].isValue:
            self._sender_kid = None

        # recipKID will be ignored. Not mentioned by cmp lightweight
        # Generally only supplied if DH keys are used
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

        self._free_text = []
        if self.pki_header['freeText'].isValue:
            for text in self.pki_header['freeText']:
                self._free_text.append(str(text))

        if self.pki_header['generalInfo'].isValue:
            raise ValueError(
                'CMP message header contains the generalInfo field. '
                'This is not yet supported by this CMP implementation.')

        self.pretty_print()


    def pretty_print(self) -> None:
        transaction_id = self.transaction_id.hex() if isinstance(self.transaction_id, bytes) else self.transaction_id
        sender_nonce = self.sender_nonce.hex() if isinstance(self.sender_nonce, bytes) else self.sender_nonce
        recipient_nonce = self.recipient_nonce.hex() \
            if isinstance(self.recipient_nonce, bytes) else self.recipient_nonce
        print('CMP Header:')
        print('-----------\n')

        print(f'PVNO:\t\t\t\t{self.pvno}')
        print(f'Sender:\t\t\t\t{self.sender}')
        print(f'Sender KID:\t\t\t{self.sender_kid}')
        print(f'Recipient:\t\t\t{self.recipient}')
        print(f'Recipient KID:\t\t\t{self.recipient_kid}')
        print(f'Message Time:\t\t\t{self.message_time}')
        print(f'Protection Algorithm:\t\t{self.protection_algorithm}')
        print(f'Transaction ID:\t\t\t{transaction_id}')
        print(f'Sender Nonce:\t\t\t{sender_nonce}')
        print(f'Recipient Nonce:\t\t{recipient_nonce}')
        print(f'Free Text:\t\t\t{self.free_text}')
        print(f'General Info:\t\t\t{self.general_info}')

    @property
    def pki_header(self) -> rfc4210.PKIHeader:
        return self._pki_header

    @property
    def pvno(self) -> int:
        return self._pvno

    @property
    def sender_kid(self) -> None | int:
        return self._sender_kid

    @property
    def sender(self) -> x509.GeneralName:
        return self._sender

    @property
    def recipient_kid(self) -> None | int:
        return self._recipient_kid

    @property
    def recipient(self) -> x509.GeneralName:
        return self._recipient

    @property
    def message_time(self) -> None | datetime.datetime:
        return self._message_time

    @property
    def protection_algorithm(self) -> ProtectionAlgorithm:
        return self._protection_algorithm

    @property
    def transaction_id(self) -> None | bytes:
        return self._transaction_id

    @property
    def sender_nonce(self) -> None | bytes:
        return self._sender_nonce

    @property
    def recipient_nonce(self) -> None | bytes:
        return self._recipient_nonce

    @property
    def free_text(self) -> list[str]:
        return self._free_text

    @property
    def general_info(self) -> None | str:
        return self._general_info


#
# class PkiMessageProtection:
#
#     _pki_protection: PKIProtection
#     _protection_value: bytes
#
#     def __init__(self, pki_protection: PKIProtection) -> None:
#         if not pki_protection.isValue:
#             raise ValueError('Protection is missing on CMP message.')
#         self._pki_protection = pki_protection
#
#         self._protection_value = pki_protection.asOctets()
#
#     @property
#     def pki_protection(self) -> PKIProtection:
#         return self._pki_protection
#
#     @property
#     def protection_value(self) -> bytes:
#         return self._protection_value
#
#
#
# class PkiMessageBody:
#
#     _pki_body: PKIBody
#
#     def __init__(self, pki_body: PKIBody) -> None:
#         if not pki_body.isValue:
#             raise ValueError('Body is missing on CMP message.')
#         self._pki_body = pki_body
#
#
#     @property
#     def pki_body(self) -> PKIBody:
#         return self._pki_body
#
#
# class CertificateTemplate:
#
#     _certificate_template: CertTemplate
#
#     _version: None | int = None
#     _serial_number: None | str = None
#
#     def __init__(self, certificate_template: CertTemplate) -> None:
#         self._certificate_template = certificate_template
#
#         if self.certificate_template['version'].isValue:
#             version = int(self.certificate_template['version'])
#             if version != 3:
#                 raise ValueError(
#                     f'Certificate template contains version {version}, but only version 3 is supported.')
#             self._version = version
#
#         if self.certificate_template['serialNumber'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         if self.certificate_template['signingAlg'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         if self.certificate_template['issuer'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         if self.certificate_template['validity'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         if self.certificate_template['subject'].isValue:
#             rdns_sequence = self.certificate_template['subject'][0]
#             if rdns_sequence.isValue:
#                 crypto_rdns_sequence: list[x509.RelativeDistinguishedName] = []
#                 for rdns in rdns_sequence:
#                     if len(rdns) < 1:
#                         raise ValueError('Found empty RDN in the subject field of the certTemplate.')
#                     if len(rdns) > 1:
#                         raise ValueError('This CMP implementation does not support multi-valued RDNs.')
#
#                     attribute_type_and_value = rdns[0]
#                     if not attribute_type_and_value.isValue or \
#                             not attribute_type_and_value['type'].isValue or \
#                             not attribute_type_and_value['value'].isValue:
#                         raise ValueError('Found empty RDN in the subject field of the certTemplate.')
#
#                     attribute_type = attribute_type_and_value['type']
#                     crypto_oid = x509.ObjectIdentifier(str(attribute_type))
#
#                     attribute_value = attribute_type_and_value['value']
#                     decoded_attribute_value, _ = decoder.decode(attribute_value)
#
#                     if isinstance(decoded_attribute_value, UTF8String):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value))
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, NumericString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.NumericString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, PrintableString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.PrintableString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, T61String):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.T61String)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, IA5String):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.IA5String)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, VisibleString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.VisibleString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, UniversalString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.UniversalString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, BMPString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.BMPString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, BitString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     bytes(decoded_attribute_value),
#                                     _type=_ASN1Type.BitString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, OctetString):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.OctetString)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, UTCTime):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.UTCTime)
#                             ]
#                         ))
#                         continue
#
#                     if isinstance(decoded_attribute_value, GeneralizedTime):
#                         crypto_rdns_sequence.append(x509.RelativeDistinguishedName(
#                             [
#                                 x509.NameAttribute(
#                                     crypto_oid,
#                                     str(decoded_attribute_value),
#                                     _type=_ASN1Type.GeneralizedTime)
#                             ]
#                         ))
#                         continue
#
#                     raise ValueError(
#                         f'Found NameAttribute in an RDN with unknown value type: {type(decoded_attribute_value)}.')
#
#                 self._subject = x509.Name(crypto_rdns_sequence)
#
#         if self.certificate_template['publicKey'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         if self.certificate_template['issuerUID'].isValue:
#             raise ValueError(
#                 'This CMP implementation does now allow to issue certificates with issuerUID set. '
#                 'This certificate field is deprecated.')
#
#         if self.certificate_template['subjectUID'].isValue:
#             raise ValueError(
#                 'This CMP implementation does now allow to issue certificates with issuerUID set. '
#                 'This certificate field is deprecated.')
#
#         if self.certificate_template['extensions'].isValue:
#             # TODO(AlexHx8472): Handle SN
#             pass
#
#         print(self.subject)
#
#
#     @property
#     def certificate_template(self) -> CertTemplate:
#         return self._certificate_template
#
#     @property
#     def version(self) -> None | int:
#         return self._version
#
#     @property
#     def serial_number(self) -> None | str:
#         return self._serial_number
#
#     @property
#     def subject(self) -> x509.Name:
#         return self._subject
#
#
# class CertRequestMessages(PkiMessageBody):
#
#     _certificate_request_message: CertReqMsg
#     _certificate_request: CertRequest
#
#     _certificate_template: CertificateTemplate
#
#     _popo: None | str
#     _reg_info: None | str
#
#     _certificate_request_id = int
#
#
#     def __init__(self, pki_body: PKIBody) -> None:
#         super().__init__(pki_body)
#
#         number_of_cert_req_messages = len(self.pki_body[0])
#         if number_of_cert_req_messages < 1:
#             raise ValueError('CMP message body (CertReqMessages) is missing the request.')
#         if number_of_cert_req_messages > 1:
#             raise ValueError('This CMP implementation only support a single CertReqMessage per request.')
#
#         if not self.pki_body[0][0].isValue:
#             raise ValueError('The CertReqMsg is emtpy.')
#         self._certificate_request_message = self.pki_body[0][0]
#
#         if not self.certificate_request_message['certReq'].isValue:
#             raise ValueError('Missing certReq field in CertReqMsg.')
#         self._certificate_request = self.certificate_request_message['certReq']
#
#         if not self.certificate_request_message[1].isValue:
#             self._popo = None
#         else:
#             # TODO(AlexHx8472): Handle POPO
#             pass
#
#         if not self.certificate_request_message[2].isValue:
#             self._reg_info = None
#         else:
#             # TODO(AlexHx8472): Handle reg info
#             pass
#
#         if not self.certificate_request['certReqId'].isValue:
#             raise ValueError('Missing certReqId field in CertReqMsg.')
#         cert_req_id = int(self.certificate_request['certReqId'])
#         if cert_req_id != 0:
#             raise ValueError(
#                 'This CMP implementation only supports a single request per cmp message, but certReqId is not 0.')
#         self._certificate_request_id = cert_req_id
#
#         if not self.certificate_request['certTemplate'].isValue:
#             raise ValueError('Missing certTemplate in CertReqMsg.')
#         self._certificate_template = CertificateTemplate(self.certificate_request['certTemplate'])
#
#         if self.certificate_request['controls'].isValue:
#             raise ValueError('Controls field in certRequest found. This is not supported by this CMP implementation.')
#
#     @property
#     def certificate_request_message(self) -> CertReqMsg:
#         return self._certificate_request_message
#
#     @property
#     def certificate_request(self) -> CertRequest:
#         return self._certificate_request
#
#     @property
#     def certificate_request_id(self) -> int:
#         return self._certificate_request_id
#
#     @property
#     def certificate_template(self) -> CertificateTemplate:
#         return self._certificate_template
#
# class PkiMessage:
#
#     _header: PkiMessageHeader
#     _body: PkiMessageBody
#     _protection: PkiMessageProtection
#
#     _pvno: int
#     _message_type: PkiMessageType
#     _popo: Popo
#
#     def __init__(self, pki_message: bytes) -> None:
#         try:
#             self._pki_message, _ = decoder.decode(pki_message, asn1Spec=PKIMessage())
#         except Exception as exception:
#             raise ValueError('Failed to parse the cmp message.') from exception
#
#         self._pvno = int(self.pki_message['header']['pvno'])
#         self._message_type = PkiMessageType(self.pki_message['body'].getName())
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
#
#     @property
#     def pvno(self) -> int:
#         return self._pvno
#
#     @property
#     def message_type(self) -> PkiMessageType:
#         return self._message_type
#
#     @property
#     def number_of_message(self) -> int:
#         return self._number_of_message
#
#     @property
#     def pki_message(self) -> PKIMessage:
#         return self._pki_message
#
#     def pretty_print(self) -> None:
#         print(self.pki_message.prettyPrint())
#
#     @property
#     def header(self) -> PkiMessageHeader:
#         return self._pki_message.header
#
#
# class InitializationRequest(PkiMessage):
#
#     def __init__(self, pki_message: bytes) -> None:
#         super().__init__(pki_message)
#
#         if self.message_type != PkiMessageType.IR:
#             raise ValueError(f'Expected CMP initialization request (ir), but found {self.message_type.value}.')
#
#         self._check_ir_header()
#         self._check_ir_body()
#         self._check_ir_protection()
#         self._check_ir_extra_certs()
#
#     def _check_ir_header(self) -> None:
#         pass
#
#     def _check_ir_body(self) -> None:
#         pass
#
#     def _check_ir_protection(self) -> None:
#         pass
#
#     def _check_ir_extra_certs(self) -> None:
#         pass
