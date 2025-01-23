from __future__ import annotations

from pyasn1.codec.der import decoder, encoder


from cryptography import x509
from cryptography.x509.name import _ASN1Type as X509_Asn1Type
import datetime

from pyasn1.type import univ
from pyasn1_modules import rfc2459, rfc4210, rfc2511
from cmp.message.protection_alg import ProtectionAlgorithmParser, ProtectionAlgorithm
from core.serializer import PublicKeySerializer
from cryptography.hazmat.primitives import serialization
from .oid import CmpMessageType
from pyasn1.type.tag import Tag
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

        pvno = int(self.pki_header['pvno'])
        if pvno not in (2, 3):
            raise ValueError('This CMP implementation only supports CMPv2 and CMPv3.')
        self._pvno = pvno

        # TODO(AlexHx8472): Currently not supporting any KID fields
        # unclear of the structure -> RFC 2459 : Octetstring,
        # however RFC4210 and RFC9483 also allow common name / directory name

        # CMP lightweight requires this for mac and signature based protection, however the OSSL CMP client leaves
        # it blank for mac based protection.
        if self.pki_header['senderKID'].isValue:
            self._sender_kid = int(self.pki_header['senderKID'].asOctets().decode())

        # recipKID will be ignored. Not mentioned by cmp lightweight
        # Generally only supplied if DH keys are used
        if not self.pki_header['recipKID'].isValue:
            self._recipient_kid = None

        self._sender = NameParser.parse_general_name(header['sender'])
        self._recipient = NameParser.parse_general_name(header['recipient'])

        if self.pki_header['messageTime'].isValue:
            self._message_time = datetime.datetime.strptime(
                str(self.pki_header['messageTime']), '%Y%m%d%H%M%SZ')

        if not self.pki_header['protectionAlg'].isValue:
            raise ValueError(
                'This CMP implementation requires protected CMP messages and a set protectionAlg field in the header.')
        self._protection_algorithm = ProtectionAlgorithmParser.parse_protection_algorithm(header['protectionAlg'])

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
        
    def __str__(self) -> str:
        transaction_id = self.transaction_id.hex() if isinstance(self.transaction_id, bytes) else self.transaction_id
        sender_nonce = self.sender_nonce.hex() if isinstance(self.sender_nonce, bytes) else self.sender_nonce
        recipient_nonce = self.recipient_nonce.hex() \
            if isinstance(self.recipient_nonce, bytes) else self.recipient_nonce
        return f"""\nCMP Header:
-----------
PVNO:                       {self.pvno}
Sender KID:                 {self.sender_kid}
Recipient KID:              {self.recipient_kid}
Sender:                     {self.sender}
Recipient:                  {self.recipient}
Message Time:               {self.message_time}
Protection Algorithm:       {self.protection_algorithm}
Transaction ID:             {transaction_id}
Sender Nonce:               {sender_nonce}
Recipient Nonce:            {recipient_nonce}
Free Text:                  {self.free_text}
General Info:               {self.general_info}"""


    def pretty_print(self) -> None:
        print(str(self))

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
    def recipient_kid(self) -> None | int:
        return self._recipient_kid

    @property
    def sender(self) -> x509.GeneralName:
        return self._sender

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


class PkiMessageProtection:

    _pki_protection: rfc4210.PKIProtection

    _protection_value: None | bytes

    def __init__(self, pki_protection: rfc4210.PKIProtection) -> None:
        self._pki_protection = pki_protection
        if self.pki_protection.isValue:
            self._protection_value = self.pki_protection.asOctets()
        else:
            self._protection_value = None

    @property
    def pki_protection(self) -> rfc4210.PKIProtection:
        return self._pki_protection

    @property
    def protection_value(self) -> None | bytes:
        return self._protection_value

    def __str__(self) -> str:
        protection = self.protection_value.hex() if isinstance(self.protection_value, bytes) else self.protection_value
        return f"""\nPKI-Protection:
-----------------
Protection (Bitstring):             {protection}"""

    def pretty_print(self) -> None:
        print(str(self))


class PkiMessageExtraCerts:

    _pyasn1: univ.SequenceOf

    _native: list[x509.Certificate]

    def __init__(self, extra_certs: list[x509.Certificate] | univ.SequenceOf) -> None:
        if isinstance(extra_certs, univ.SequenceOf):
            self.pyasn1 = extra_certs
        elif isinstance(extra_certs, list):
            for certificate in extra_certs:
                if not isinstance(certificate, x509.Certificate):
                    raise TypeError('ExtraCerts must either be a univ.SequenceOf or a list[x509.Certificate].')
            self.native = extra_certs
        else:
            raise TypeError('ExtraCerts must either be a univ.SequenceOf or a list[x509.Certificate].')

    @property
    def pyasn1(self) -> univ.SequenceOf:
        return self._pyasn1

    @pyasn1.setter
    def pyasn1(self, pyasn1: univ.SequenceOf) -> None:
        self._pyasn1 = pyasn1
        self._native = []
        # TODO: set native

    @property
    def native(self) -> list[x509.Certificate]:
        return self._native

    @native.setter
    def native(self, native: list[x509.Certificate]) -> None:
        self._native = native
        # TODO: set pyasn1

    def __str__(self) -> str:
        result =  f'\nExtra-Certs:\n------------\n'
        if self.native:
            for index, certificate in enumerate(self.native):
                result += f'Certificate {index}:      {certificate.subject.rfc4514_string()}\n'
        else:
            result += 'No extra certificates.\n'
        return result

    def pretty_print(self) -> None:
        print(str(self))


class PkiMessageBody:

    _pyasn1: rfc4210.PKIBody
    _message_type: CmpMessageType

    def __init__(self, pki_body: rfc4210.PKIBody) -> None:
        if not pki_body.isValue:
            raise ValueError('Body is missing on CMP message.')
        self._pyasn1 = pki_body
        self._message_type = CmpMessageType(pki_body.getName().lower())

        if self._message_type in (CmpMessageType.IR, CmpMessageType.CR):
            if len(self.pyasn1.getComponent()) > 1:
                raise ValueError('This CMP implementation only supports a single certificate request per cmp message.')
            _certificate_request = self.pyasn1.getComponent()[0]
        else:
            raise NotImplementedError(f'Message type: {self.message_type} not yet implemented.')

    @property
    def pyasn1(self) -> rfc4210.PKIBody:
        return self._pyasn1

    @property
    def message_type(self) -> CmpMessageType:
        return self._message_type


class PkiMessage:

    _header: PkiMessageHeader
    _body: PkiMessageBody
    _protection: PkiMessageProtection
    _extra_certs: PkiMessageExtraCerts

    _message_type:CmpMessageType

    def __init__(self, pki_message: rfc4210.PKIMessage) -> None:
        self._header = PkiMessageHeader(pki_message['header'])
        self._message_type = CmpMessageType(pki_message['body'].getName().lower())
        self._body = PkiMessageBody(pki_message['body'])
        self._protection = PkiMessageProtection(pki_message['protection'])
        self._extra_certs = PkiMessageExtraCerts(pki_message['extraCerts'])

    @property
    def header(self) -> PkiMessageHeader:
        return self._header

    @property
    def body(self) -> PkiMessageBody:
        return self._body

    @property
    def protection(self) -> PkiMessageProtection:
        return self._protection

    @property
    def extra_certs(self) -> PkiMessageExtraCerts:
        return self._extra_certs

class PkiIrMessage(PkiMessage):

    _request_template: PkiRequestTemplate

    def __init__(self, pki_message: rfc4210.PKIMessage) -> None:
        if CmpMessageType(pki_message['body'].getName().lower()) != CmpMessageType.IR:
            raise ValueError('PkiIrMessage must be an actual IR message.')
        super().__init__(pki_message)
        if len(self.body.pyasn1.getComponent()) < 1:
            raise ValueError('Certificate request missing in CMP request message.')
        if len(self.body.pyasn1.getComponent()) > 1:
            raise ValueError('This CMP implementation does only support a single certificate request per cmp message.')
        self._request_template = PkiRequestTemplate(self.body.pyasn1.getComponent()[0]['certReq']['certTemplate'])

    @property
    def request_template(self) -> PkiRequestTemplate:
        return self._request_template


class PkiRequestTemplate:

    _cert_template: rfc2511.CertTemplate

    def __init__(self, cert_template: rfc2511.CertTemplate) -> None:
        if not cert_template.isValue:
            raise ValueError('Certificate template missing.')
        self._cert_template = cert_template

    @property
    def subject(self) -> None | x509.Name:
        if self._cert_template['subject'].isValue:
            return NameParser.parse_name(self._cert_template['subject'])
        return None

    @property
    def serial_number(self) -> None | int:
        if self._cert_template['serialNumber'].isValue:
            return int(self._cert_template['serialNumber'])
        else:
            return None

    @property
    def public_key(self) -> None | PublicKeySerializer:
        if not self._cert_template['publicKey'].isValue:
            return None
        spki = rfc2511.SubjectPublicKeyInfo()
        spki.setComponentByName('algorithm', self._cert_template['publicKey']['algorithm'])
        spki.setComponentByName('subjectPublicKey', self._cert_template['publicKey']['subjectPublicKey'])

        return PublicKeySerializer(serialization.load_der_public_key(encoder.encode(spki)))

    @property
    def not_valid_before(self) -> None | datetime.datetime:
        if not self._cert_template['validity'].isValue:
            return None
        if not self._cert_template['validity'][0].isValue:
            return None
        return datetime.datetime.strptime(
            str(self._cert_template['validity'][0]), '%Y%m%d%H%M%SZ')

    @property
    def not_valid_after(self) -> None | datetime.datetime:
        if not self._cert_template['validity'].isValue:
            return None
        if not self._cert_template['validity'][1].isValue:
            return None
        return datetime.datetime.strptime(
            str(self._cert_template['validity'][1]), '%Y%m%d%H%M%SZ')
