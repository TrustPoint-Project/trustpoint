import secrets

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1_modules import rfc4210, rfc5280, rfc2459
from pyasn1.codec.der import decoder, encoder
import datetime
from pyasn1.type import useful
from pyasn1.type import univ, char, useful, tag, constraint



class CmpErrorMessageHeaderBuilder:

    _received_pyasn1_header: None | rfc4210.PKIHeader

    def __init__(self, received_pyasn1_header: None | rfc4210.PKIHeader, signer_cert: x509.Certificate):
        self._received_pyasn1_header = received_pyasn1_header
        self._error_msg_header = rfc4210.PKIHeader()



        self._error_msg_header['pvno'] = 2
        self._error_msg_header['sender'] = self._get_general_name_from_cert_subject(signer_cert)
        self._error_msg_header['recipient'] = self._received_pyasn1_header['sender']
        self._error_msg_header['messageTime'] = useful.GeneralizedTime(
            datetime. datetime. now(datetime. UTC).strftime('%Y%m%d%H%M%SZ')
        ).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        print(signer_cert.public_key_algorithm_oid)
        # self._error_msg_header['protectionAlg'] = from cert signer
        self._error_msg_header['senderKID'] = self._get_subject_key_identifier_from_cert(signer_cert)

        # recipKID not for error messages (Only for DH keys, which are not used in error messages)

        if self._received_pyasn1_header['transactionID'].hasValue():
            self._error_msg_header['transactionID'] = self._received_pyasn1_header['transactionID']

        self._error_msg_header['senderNonce'] = secrets.token_bytes(16)

        if self._received_pyasn1_header['senderNonce'].hasValue():
            self._error_msg_header['recipNonce'] = univ.OctetString(
                self._received_pyasn1_header['senderNonce']
            ).subtype(
                 explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
            )
        # freeText not for error message
        # generalInfo not for error message

        print(self._error_msg_header.prettyPrint())

    @staticmethod
    def _get_general_name_from_cert_subject(certificate: x509.Certificate) -> rfc5280.GeneralName:
        subject_bytes = certificate.subject.public_bytes()
        name, _ = decoder.decode(subject_bytes, asn1spec=rfc2459.Name())
        general_name = rfc2459.GeneralName()
        general_name['directoryName'].setComponentByPosition(0, name)
        return general_name

    @staticmethod
    def _get_subject_key_identifier_from_cert(certificate: x509.Certificate) -> rfc4210.KeyIdentifier:
        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest

        return rfc4210.KeyIdentifier(subject_key_identifier).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )