from __future__ import annotations

from pyasn1_modules.rfc4210 import CertOrEncCert

from core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc4210, rfc2511, rfc2459, rfc5280
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.http import HttpResponse

from typing import TYPE_CHECKING, Protocol, cast
from devices.models import DeviceModel, DomainModel, TrustpointClientOnboardingProcessModel
from devices.issuer import LocalDomainCredentialIssuer
from cmp.message.cmp import PkiIrMessage, NameParser
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
from pyasn1.type import univ, tag, useful
import secrets
import datetime


if TYPE_CHECKING:
    from django.http import HttpRequest
    from typing import Any


class Dispatchable(Protocol):
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        ...


class CmpHttpMixin:

    expected_content_type = 'application/pkixcmp'
    max_payload_size = 131072   # max 128 KiByte
    raw_message: bytes


    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        self.raw_message = request.read()
        if len(self.raw_message) > self.max_payload_size:
             return HttpResponse('Message is too large.', status=413)

        content_type = request.headers.get('Content-Type')
        if content_type is None:
            return HttpResponse(
                'Message is missing the content type.', status=415)

        if content_type != self.expected_content_type:
            return HttpResponse(
                f'Message does not have the expected content type: {self.expected_content_type}.', status=415)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpRequestedDomainExtractorMixin:

    requested_domain: DomainModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        domain_name = cast(str, kwargs.get('domain'))

        try:
            self.requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return HttpResponse('Domain does not exist.', status=404)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpPkiMessageSerializerMixin:

    raw_message: bytes
    serialized_pyasn1_message: None | rfc4210.PKIMessage

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            self.serialized_pyasn1_message, _ = decoder.decode(self.raw_message, asn1Spec=rfc4210.PKIMessage())
        except (ValueError, TypeError):
            return HttpResponse('Failed to parse the CMP message. Seems to be corrupted.', status=400)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


# class CmpIrMessageSerializerMixin:
#
#     serialized_pyasn1_message: None | rfc4210.PKIMessage
#     serialized_ir_message: None | PkiIrMessage
#
#     # requested_domain: DomainModel
#     onboarding_process: None | TrustpointClientOnboardingProcessModel
#
#     def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
#         try:
#             self.serialized_ir_message = PkiIrMessage(self.serialized_pyasn1_message)
#         except (ValueError, TypeError):
#             return HttpResponse(f'Expected CMP IR message, but got {self.serialized_pyasn1_message["body"].getName()}.')
#
#         if self.serialized_ir_message.header.protection_algorithm == ProtectionAlgorithmOid.PASSWORD_BASED_MAC:
#             onboarding_process_id = self.serialized_ir_message.request_template.subject.get_attributes_for_oid(
#                 x509.NameOID.USER_ID
#             )
#
#             if not onboarding_process_id:
#                 return HttpResponse('Failed to obtain onboarding process ID.', status=404)
#
#             if len(onboarding_process_id) > 1:
#                 return HttpResponse('Found multiple UIDs in the request subject.')
#
#         parent = cast(Dispatchable, super())
#         return parent.dispatch(request, *args, **kwargs)


class CmpOnboardingAuthenticationMixin:

    serialized_pyasn1_message: rfc4210.PKIMessage
    serialized_ir_message: PkiIrMessage
    onboarding_process: None | TrustpointClientOnboardingProcessModel
    device: DeviceModel
    requested_domain: DomainModel


    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
    #     if self.serialized_ir_message.header.protection_algorithm.oid == ProtectionAlgorithmOid.PASSWORD_BASED_MAC:
    #         sender_kid = self.serialized_ir_message.header.sender_kid
    #         if sender_kid is None:
    #             return HttpResponse(
    #                 'SenderKID is missing in the CMP message, but required for PBM protected messages.',
    #                 status=404)
    #
    #         try:
    #             self.device = DeviceModel.objects.get(id=sender_kid)
    #         except DeviceModel.DoesNotExist:
    #             return HttpResponse('Device not found.', status=404)
    #
    #         try:
    #             self.onboarding_process = TrustpointClientOnboardingProcessModel.objects.get(device=self.device)
    #         except TrustpointClientOnboardingProcessModel.DoesNotExist:
    #             return HttpResponse(
    #                 f'No active onboarding process found for device {self.device.unique_name}.',
    #                 status=404)
    #
    #         pbm_choice_value = TrustpointClientOnboardingProcessModel.AuthenticationMethod.PASSWORD_BASED_MAC.value
    #         if self.onboarding_process.auth_method != pbm_choice_value:
    #             return HttpResponse(
    #                 f'PBM protection for device {self.device.unique_name} not allowed.',
    #                 status=404)
    #
    #         if not self._pbm_protection_is_valid():
    #             return HttpResponse(
    #                 f'PBM protection verification failed.',
    #                 status=404
    #             )
    #
    #     else:
    #         # TODO(AlexHx8472): still WIP
    #         serial_number_attributes = self.serialized_ir_message.request_template.subject.get_attributes_for_oid(
    #             x509.NameOID.SERIAL_NUMBER)
    #
    #         if not serial_number_attributes:
    #             return HttpResponse('Serial-number missing in cmp request template.', status=404)
    #
    #         if len(serial_number_attributes) > 1:
    #             return HttpResponse(
    #                 'Found multiple serial number attributes in the cmp request template',
    #                 status=404)
    #
    #         serial_number = serial_number_attributes[0].value
    #
    #         try:
    #             self.device = DeviceModel.objects.get(serial_number__iexact=serial_number)
    #         except DeviceModel.DoesNotExist:
    #             return HttpResponse('Device not found.', status=404)
    #
    #         try:
    #             self.onboarding_process = TrustpointClientOnboardingProcessModel.objects.get(device=self.device)
    #         except TrustpointClientOnboardingProcessModel.DoesNotExist:
    #             return HttpResponse(
    #                 f'No active onboarding process found for device {self.device.unique_name}.',
    #                 status=404)
    #
    #         if not self._signature_protection_is_valid():
    #             return HttpResponse('Signature verification failed.', status=404)
    #
    #
        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)
    #
    # def _pbm_protection_is_valid(self) -> bool:
    #     shared_secret = self.onboarding_process.password.encode()
    #
    #     protected_part = rfc4210.ProtectedPart()
    #     protected_part.setComponentByName('header', self.serialized_pyasn1_message['header'])
    #     protected_part.setComponentByName('infoValue', self.serialized_pyasn1_message['body'])
    #
    #     encoded_protected_part = encoder.encode(protected_part)
    #
    #     # TODO(BytesWelder): PBM verification
    #
    #     return True
    #
    # def _signature_protection_is_valid(self) -> bool:
    #
    #     # TODO(BytesWelder): Signature verification
    #
    #     return True

class CmpOnboardingAuthorizationMixin:

    requested_domain: DomainModel
    requested_device: DeviceModel
    onboarding_process: TrustpointClientOnboardingProcessModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        # if self.requested_domain != self.onboarding_process.device.domain:
        #     return HttpResponse(
        #         f'The requested domain {self.requested_domain.unique_name} is '
        #         f'not available for device {self.onboarding_process.device.unique_name}',
        #         status=404
        #     )
        #
        # # TODO(AlexHx8472): For signature based auth -> check if signer is allowed to issue certificate for
        # # TODO(AlexHx8472): the specific domain and device / check if type of cert is allowed.

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(
        CmpHttpMixin,
        CmpRequestedDomainExtractorMixin,
        CmpPkiMessageSerializerMixin,
        # CmpIrMessageSerializerMixin,
        CmpOnboardingAuthenticationMixin,
        CmpOnboardingAuthorizationMixin,
        View):

    http_method_names = ('post', )

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    requested_domain: DomainModel
    onboarding_process: TrustpointClientOnboardingProcessModel

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:

        if self.serialized_pyasn1_message['header']['pvno'] != 2:
            print('pvno fail')
            raise ValueError

        protection_algorithm = AlgorithmIdentifier(
            self.serialized_pyasn1_message['header']['protectionAlg']['algorithm'].prettyPrint())
        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:

            # openssl cmp -server http://localhost:8000/.well -known/cmp/initialization/phoenix_contact/
            # -cmd ir -secret pass:mhBaszVCYMClCZoG -subject "/CN=Trustpoint Domain Credential"
            # -newkey key.pem -certout cert.pem -ref 29 -implicit_confirm -chainout chain.pem

            sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
            self.onboarding_process = TrustpointClientOnboardingProcessModel.objects.get(device__pk=sender_kid)

            transaction_id = self.serialized_pyasn1_message['header']['transactionID'].asOctets()
            if len(transaction_id) != 16:
                print('transactionID fail')
                raise ValueError

            sender_nonce = self.serialized_pyasn1_message['header']['senderNonce'].asOctets()
            if len(sender_nonce) != 16:
                print('senderNonce fail')
                raise ValueError

            IMPLICIT_CONFIRM_OID = '1.3.6.1.5.5.7.4.13'
            IMPLICIT_CONFIRM_STR_VALUE = '0x0500'
            implicit_confirm_entry = None
            for entry in self.serialized_pyasn1_message['header']['generalInfo']:
                if entry['infoType'].prettyPrint() == IMPLICIT_CONFIRM_OID:
                    implicit_confirm_entry = entry
                    break
            if implicit_confirm_entry is None:
                print('implicit confirm missing')
                raise ValueError

            if implicit_confirm_entry['infoValue'].prettyPrint() != IMPLICIT_CONFIRM_STR_VALUE:
                print('implicit confirm entry fail')
                raise ValueError

            protection_value = self.serialized_pyasn1_message['protection'].asOctets()

            # ignore extra certs

            if self.serialized_pyasn1_message['body'].getName() != 'ir':
                print('not ir message')
                raise ValueError

            ir_body = self.serialized_pyasn1_message['body']['ir']
            if len(ir_body) > 1:
                print('multiple CertReqMessages found for IR.')
                raise ValueError

            if len(ir_body) < 1:
                print('no CertReqMessages found for IR.')
                raise ValueError

            cert_req_msg = ir_body[0]['certReq']

            if cert_req_msg['certReqId'] != 0:
                print('certReqId must be 0.')
                raise ValueError

            if not cert_req_msg['certTemplate'].hasValue():
                print('certTemplate must be contained in IR CertReqMessage.')
                raise ValueError

            cert_req_template = cert_req_msg['certTemplate']

            if cert_req_template['version'].hasValue():
                if cert_req_template['version'] != 2:
                    print('Version must be 2 if supplied in certificate request.')

            if not cert_req_template['subject'].isValue:
                print('subject missing in CertReqMessage.')
                raise ValueError

            # ignores subject request for now and forces values to set
            subject = NameParser.parse_name(cert_req_template['subject'])

            # only local key-gen supported currently -> public key must be present
            asn1_public_key = cert_req_template['publicKey']
            if not asn1_public_key.hasValue():
                print('Public-missing in CertTemplate.')
                raise ValueError

            # cloned_pk = asn1_public_key.clone(tagSet=rfc2511.SubjectPublicKeyInfo.tagSet)
            # print(cloned_pk.prettyPrint())
            spki = rfc2511.SubjectPublicKeyInfo()
            spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
            spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
            loaded_public_key = load_der_public_key(encoder.encode(spki))

            # ignore popo for now
            popo = ir_body[0]['pop'].prettyPrint()
            # TODO(AlexHx8472): verify popo / process popo

            # pbm validation

            pbm_parameters_bitstring = self.serialized_pyasn1_message['header']['protectionAlg']['parameters']
            decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

            salt = decoded_pbm['salt'].asOctets()
            try:
                owf = HashAlgorithm(decoded_pbm['owf']['algorithm'].prettyPrint())
            except Exception as e:
                print('owf algorithm not supported.')
                raise e
            iteration_count = int(decoded_pbm['iterationCount'])

            shared_secret = self.onboarding_process.password.encode()
            salted_secret = shared_secret + salt
            hmac_key = salted_secret
            for _ in range(iteration_count):
                hasher = hashes.Hash(owf.hash_algorithm())
                hasher.update(hmac_key)
                hmac_key = hasher.finalize()

            hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
            try:
                hmac_algorithm = HmacAlgorithm(hmac_algorithm_oid)
            except Exception as e:
                print('hmac algorithm not supported.')
                raise e

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = self.serialized_pyasn1_message['header']
            protected_part['infoValue'] = self.serialized_pyasn1_message['body']

            encoded_protected_part = encoder.encode(protected_part)

            hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
            hmac_gen.update(encoded_protected_part)

            try:
                hmac_gen.verify(protection_value)
            except InvalidSignature as exception:
                print('hmac verification failed.')
                print(exception)

            # Checks regarding contained public key and corresponding signature suite of the issuing CA

            issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
            signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
            if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                raise ValueError('Contained public key type does not match the signature suite.')


            domain_credential_issuer = LocalDomainCredentialIssuer(
                domain=self.requested_domain, device=self.onboarding_process.device
            )

            issued_domain_credential_model = domain_credential_issuer.issue_domain_credential(
                public_key=loaded_public_key
            )

            ip_header = rfc4210.PKIHeader()

            ip_header['pvno'] = 2

            issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
            raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
            name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
            sender = rfc2459.GeneralName()
            sender['directoryName'][0] = name
            ip_header['sender'] = sender

            ip_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

            current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
            ip_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

            ip_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

            ip_header['senderKID'] = self.serialized_pyasn1_message['header']['senderKID']

            ip_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

            ip_header['senderNonce'] = univ.OctetString(secrets.token_bytes(16)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))

            ip_header['recipNonce'] = univ.OctetString(self.serialized_pyasn1_message['header']['senderNonce']).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))

            ip_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

            # ip extra certs

            ip_extra_certs = univ.SequenceOf()

            certificate_chain = [
                self.requested_domain.issuing_ca.credential.get_certificate()
            ] + self.requested_domain.issuing_ca.credential.get_certificate_chain()
            for certificate in certificate_chain:
                der_bytes = certificate.public_bytes(encoding=Encoding.DER)
                asn1_certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc4210.CMPCertificate())
                ip_extra_certs.append(asn1_certificate)

            # body
            ip_body = rfc4210.PKIBody()
            ip_body['ip'] = rfc4210.CertRepMessage().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
            ip_body['ip']['caPubs'] = univ.SequenceOf().subtype(
                sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
            # TODO(AlexHx8472): Add TLS Server Certificate Root CA
            root_ca_cert = self.requested_domain.issuing_ca.credential.get_root_ca_certificate()
            # if root_ca_cert:
            #     der_bytes = root_ca_cert.public_bytes(encoding=Encoding.DER)
            #     asn1_certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc4210.CMPCertificate())
            #     ip_body['ip']['caPubs'].append(asn1_certificate)

            cert_response = rfc4210.CertResponse()
            cert_response['certReqId'] = 0

            pki_status_info = rfc4210.PKIStatusInfo()
            pki_status_info['status'] = 0
            cert_response['status'] = pki_status_info

            cmp_cert = rfc4210.CMPCertificate().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

            encoded_cert = issued_domain_credential_model.credential.get_certificate().public_bytes(
                encoding=Encoding.DER)
            der_cert, _ = decoder.decode(encoded_cert, asn1Spec=rfc4210.CMPCertificate())
            cmp_cert.setComponentByName("tbsCertificate", der_cert['tbsCertificate'])
            cmp_cert.setComponentByName("signatureValue", der_cert['signatureValue'])
            cmp_cert.setComponentByName("signatureAlgorithm", der_cert['signatureAlgorithm'])
            cert_or_enc_cert = rfc4210.CertOrEncCert()
            cert_or_enc_cert['certificate'] = cmp_cert

            cert_response['certifiedKeyPair']['certOrEncCert'] = cert_or_enc_cert

            ip_body['ip']['response'].append(cert_response)


            ip_message = rfc4210.PKIMessage()
            ip_message['header'] = ip_header
            ip_message['body'] = ip_body
            for extra_cert in ip_extra_certs:
                ip_message['extraCerts'].append(extra_cert)

            # TODO(AlexHx8472): Use fresh salt!
            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = ip_message['header']
            protected_part['infoValue'] = ip_message['body']

            encoded_protected_part = encoder.encode(protected_part)

            hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
            hmac_gen.update(encoded_protected_part)
            hmac_digest = hmac_gen.finalize()

            binary_stuff = bin(int.from_bytes(hmac_digest, byteorder='big'))[2:].zfill(160)
            ip_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

            encoded_ip_message = encoder.encode(ip_message)
            decoded_ip_message, _ = decoder.decode(encoded_ip_message, asn1Spec=rfc4210.PKIMessage())

        else:
            # openssl cmp -server http://localhost:8000/.well -known/cmp/initialization/phoenix_contact/
            # -cmd ir -subject "/CN=Trustpoint Domain Credential" -cert cmp_signer_credential
            # -newkey key.pem -certout cert.pem -implicit_confirm -chainout chain.pem

            print(self.serialized_pyasn1_message)

            encoded_ip_message = b''


        return HttpResponse(encoded_ip_message, content_type='application/pkixcmp', status=200)
