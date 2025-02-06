# from __future__ import annotations
# import abc
#
#
# class Specification(abc.ABC):
#
#     @abc.abstractmethod
#     def is_satisfied_by(self, candidate):
#
# from pyasn1_modules import rfc4210
# from cryptography import x509
# import datetime
#
# class
#
#
#
#
#
#
# # IR message
#
# # HEADER
#
# #   pvno = 2
#
#
# # class CmpHeader:
# #
# #     _pki_header: rfc4210.PKIHeader
# #
# #     _pvno: int
# #     _sender: x509.GeneralName
# #     _sender_kid: None | int = None
# #     _recipient_kid: None | int = None
# #     _recipient: x509.GeneralName
# #     _message_time: None | datetime.datetime = None
# #     _protection_algorithm: ProtectionAlgorithm
# #     _transaction_id: None  | bytes = None
# #     _sender_nonce: None | bytes = None
# #     _recipient_nonce: None | bytes = None
# #     _free_text: list[str]
# #     _general_info: None | str = None
# #
# #     def __init__(self, header: rfc4210.PKIHeader) -> None:
# #         self._pki_header = header
# #
# #         pvno = int(self.pki_header['pvno'])
# #         if pvno not in (2, 3):
# #             raise ValueError('This CMP implementation only supports CMPv2 and CMPv3.')
# #         self._pvno = pvno
# #
# #         # unclear of the structure -> RFC 2459 : Octetstring,
# #         # however RFC4210 and RFC9483 also allow common name / directory name
# #
# #         # CMP lightweight requires this for mac and signature based protection, however the OSSL CMP client leaves
# #         # it blank for mac based protection.
# #         if self.pki_header['senderKID'].isValue:
# #             self._sender_kid = int(self.pki_header['senderKID'].asOctets().decode())
# #
# #         # recipKID will be ignored. Not mentioned by cmp lightweight
# #         # Generally only supplied if DH keys are used
# #         if not self.pki_header['recipKID'].isValue:
# #             self._recipient_kid = None
# #
# #         self._sender = NameParser.parse_general_name(header['sender'])
# #         self._recipient = NameParser.parse_general_name(header['recipient'])
# #
# #         if self.pki_header['messageTime'].isValue:
# #             self._message_time = datetime.datetime.strptime(
# #                 str(self.pki_header['messageTime']), '%Y%m%d%H%M%SZ')
# #
# #         if not self.pki_header['protectionAlg'].isValue:
# #             raise ValueError(
# #                 'This CMP implementation requires protected CMP messages and a set protectionAlg field in the header.')
# #         self._protection_algorithm = ProtectionAlgorithmParser.parse_protection_algorithm(header['protectionAlg'])
# #
# #         if not self.pki_header['transactionID'].isValue:
# #             raise ValueError('TransactionID field is missing in the CMP message header.')
# #         self._transaction_id = self.pki_header['transactionID'].asOctets()
# #
# #         if not self.pki_header['senderNonce'].isValue:
# #             raise ValueError('SenderNonce field is missing in the CMP message header.')
# #         self._sender_nonce = self.pki_header['senderNonce'].asOctets()
# #
# #         if self.pki_header['recipNonce'].isValue:
# #             self._recipient_nonce = self.pki_header['recipNonce'].asOctets()
# #
# #         self._free_text = []
# #         if self.pki_header['freeText'].isValue:
# #             for text in self.pki_header['freeText']:
# #                 self._free_text.append(str(text))
# #
# #         if self.pki_header['generalInfo'].isValue:
# #             raise ValueError(
# #                 'CMP message header contains the generalInfo field. '
# #                 'This is not yet supported by this CMP implementation.')
# #
# #     def __str__(self) -> str:
# #         transaction_id = self.transaction_id.hex() if isinstance(self.transaction_id, bytes) else self.transaction_id
# #         sender_nonce = self.sender_nonce.hex() if isinstance(self.sender_nonce, bytes) else self.sender_nonce
# #         recipient_nonce = self.recipient_nonce.hex() \
# #             if isinstance(self.recipient_nonce, bytes) else self.recipient_nonce
# #         return f"""\nCMP Header:
# # -----------
# # PVNO:                       {self.pvno}
# # Sender KID:                 {self.sender_kid}
# # Recipient KID:              {self.recipient_kid}
# # Sender:                     {self.sender}
# # Recipient:                  {self.recipient}
# # Message Time:               {self.message_time}
# # Protection Algorithm:       {self.protection_algorithm}
# # Transaction ID:             {transaction_id}
# # Sender Nonce:               {sender_nonce}
# # Recipient Nonce:            {recipient_nonce}
# # Free Text:                  {self.free_text}
# # General Info:               {self.general_info}"""