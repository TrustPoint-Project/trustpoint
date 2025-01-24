from __future__ import annotations

import hashlib
import hmac
import sys
from typing import TYPE_CHECKING, Protocol, cast

import pyasn1
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from devices.issuer import LocalDomainCredentialIssuer
from devices.models import DeviceModel, DomainModel, TrustpointClientOnboardingProcessModel
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from pki.models.credential import CredentialModel
from pki.models.issuing_ca import IssuingCaModel
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Any
from pyasn1_modules import rfc4210

from cmp.message.cmp import PkiIrMessage
from cmp.message.protection_alg import ProtectionAlgorithmOid
from tmp.util.keys import DigitalSignature

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest


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
    requested_onboarding_process: None | TrustpointClientOnboardingProcessModel

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


class CmpIrMessageSerializerMixin:

    serialized_pyasn1_message: None | rfc4210.PKIMessage
    serialized_ir_message: None | PkiIrMessage

    # requested_domain: DomainModel
    onboarding_process: None | TrustpointClientOnboardingProcessModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            self.serialized_ir_message = PkiIrMessage(self.serialized_pyasn1_message)
        except (ValueError, TypeError):
            return HttpResponse(f'Expected CMP IR message, but got {self.serialized_pyasn1_message["body"].getName()}.')

        if self.serialized_ir_message.header.protection_algorithm == ProtectionAlgorithmOid.PASSWORD_BASED_MAC:
            onboarding_process_id = self.serialized_ir_message.request_template.subject.get_attributes_for_oid(
                x509.NameOID.USER_ID
            )

            if not onboarding_process_id:
                return HttpResponse('Failed to obtain onboarding process ID.', status=404)

            if len(onboarding_process_id) > 1:
                return HttpResponse('Found multiple UIDs in the request subject.')

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpOnboardingAuthenticationMixin:

    serialized_pyasn1_message: rfc4210.PKIMessage
    serialized_ir_message: PkiIrMessage
    onboarding_process: None | TrustpointClientOnboardingProcessModel
    device: DeviceModel
    domain: DomainModel

    oid_to_hash = {
            '1.2.840.113549.1.1.11': hashes.SHA256,
            '1.2.840.113549.1.1.12': hashes.SHA384,
            '1.2.840.113549.1.1.13': hashes.SHA512,
            '1.3.6.1.5.5.8.1.2': hashes.SHA1,
            '2.16.840.1.101.3.4.2.1': hashes.SHA256,
            '2.16.840.1.101.3.4.2.2': hashes.SHA384,
            '2.16.840.1.101.3.4.2.3': hashes.SHA512
        }


    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if self.serialized_ir_message.header.protection_algorithm.oid == ProtectionAlgorithmOid.PASSWORD_BASED_MAC:
            sender_kid = self.serialized_ir_message.header.sender_kid
            if sender_kid is None:
                return HttpResponse(
                    'SenderKID is missing in the CMP message, but required for PBM protected messages.',
                    status=404)

            try:
                self.device = DeviceModel.objects.get(id=sender_kid)
            except DeviceModel.DoesNotExist:
                return HttpResponse('Device not found.', status=404)

            try:
                print('trying to get onboarding process')
                self.onboarding_process = TrustpointClientOnboardingProcessModel.objects.get(device=self.device)
            except TrustpointClientOnboardingProcessModel.DoesNotExist:
                return HttpResponse(
                    f'No active onboarding process found for device {self.device.unique_name}.',
                    status=404)

            pbm_choice_value = TrustpointClientOnboardingProcessModel.AuthenticationMethod.PASSWORD_BASED_MAC.value
            if self.onboarding_process.auth_method != pbm_choice_value:
                return HttpResponse(
                    f'PBM protection for device {self.device.unique_name} not allowed.',
                    status=404)

            if not self._pbm_protection_is_valid():
                return HttpResponse(
                    'PBM protection verification failed.',
                    status=404
                )

        else:
            # TODO(AlexHx8472): still WIP
            serial_number_attributes = self.serialized_ir_message.request_template.subject.get_attributes_for_oid(
                x509.NameOID.SERIAL_NUMBER)
            if not serial_number_attributes:
                return HttpResponse('Serial-number missing in cmp request template.', status=404)
            if len(serial_number_attributes) > 1:
                return HttpResponse(
                    'Found multiple serial number attributes in the cmp request template',
                    status=404)

            serial_number = serial_number_attributes[0].value
            try:
                self.device = DeviceModel.objects.get(serial_number__iexact=serial_number)
            except DeviceModel.DoesNotExist:
                return HttpResponse('Device not found.', status=404)

            try:
                self.onboarding_process = TrustpointClientOnboardingProcessModel.objects.get(device=self.device)
            except TrustpointClientOnboardingProcessModel.DoesNotExist:
                return HttpResponse(
                    f'No active onboarding process found for device {self.device.unique_name}.',
                    status=404)

            if not self._signature_protection_is_valid():
                return HttpResponse('Signature verification failed.', status=404)


        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)

    def _pbm_protection_is_valid(self) -> bool:
        # TODO(BytesWelder): hash to oid mapping replacement, core -> oid
        shared_secret = self.onboarding_process.password.encode()

        protected_part = rfc4210.ProtectedPart()
        protected_part.setComponentByName('header', self.serialized_pyasn1_message['header'])
        protected_part.setComponentByName('infoValue', self.serialized_pyasn1_message['body'])

        encoded_protected_part = encoder.encode(protected_part)

        # Get PBM Parameters
        protection_alg = protected_part.getComponentByName('header').getComponentByName('protectionAlg')
        parameters = protection_alg.getComponentByName('parameters')
        decoded_data, _ = decoder.decode(parameters, asn1Spec=rfc4210.PBMParameter())

        salt = decoded_data.getComponentByName('salt').asOctets()
        owf = decoded_data.getComponentByName('owf').getComponentByName('algorithm').prettyPrint()
        iteration_count = int(decoded_data.getComponentByName('iterationCount'))
        mac = decoded_data.getComponentByName('mac').getComponentByName('algorithm').prettyPrint()

        # Calculate key
        key = shared_secret + salt
        for _ in range(iteration_count):
            key = hashlib.new(self.oid_to_hash[owf].name, key).digest()

        # calculate hmac
        calculated_mac = hmac.new(key, encoded_protected_part, self.oid_to_hash[mac].name).digest()
        received_mac = self.serialized_pyasn1_message['protection'].asOctets()

        return hmac.compare_digest(calculated_mac, received_mac)


    def _signature_protection_is_valid(self) -> bool:
        protected_part = rfc4210.ProtectedPart()
        protected_part.setComponentByName('header', self.serialized_pyasn1_message['header'])
        protected_part.setComponentByName('body', self.serialized_pyasn1_message['body'])

        encoded_protected_part = encoder.encode(protected_part)

        # Get signature parameters
        protection_alg = self.serialized_pyasn1_message['header']['protectionAlg']
        signature_oid = str(protection_alg['algorithm'])
        signature = self.serialized_pyasn1_message['protection'].asOctets()

        # Get certificate from message
        sender_cert = self.serialized_pyasn1_message['header']['sender']
        sender_certificate = x509.load_der_x509_certificate(sender_cert.asOctets())


        # Get issuing ca credential
        ca_cred: CredentialModel = self.domain.issuing_ca.credential

        if sender_certificate.public_bytes() != ca_cred.certificate.subject_public_bytes:
            msg = 'Wrong issuer certificate'
            raise AttributeError(msg)

        # Verifiying the Signature
        try:
            ca_cred.certificate.get_public_key_serializer().as_crypto().verify(
                signature,
                encoded_protected_part,
                padding.PKCS1v15(),
                self.oid_to_hash[signature_oid].name
            )
            print('SIGNATURE VERIFICATION SUCCESSFUL')
            return True
        except Exception as e:
            print(f'SIGNATURE VERIFICATION FAILED: {e}')
            return False


class CmpOnboardingAuthorizationMixin:

    requested_domain: DomainModel
    requested_device: DeviceModel
    onboarding_process: TrustpointClientOnboardingProcessModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        if self.requested_domain != self.onboarding_process.device.domain:
            return HttpResponse(
                f'The requested domain {self.requested_domain.unique_name} is '
                f'not available for device {self.onboarding_process.device.unique_name}',
                status=404
            )

        # TODO(AlexHx8472): For signature based auth -> check if signer is allowed to issue certificate for
        # TODO(AlexHx8472): the specific domain and device / check if type of cert is allowed.

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(
        CmpHttpMixin,
        CmpRequestedDomainExtractorMixin,
        CmpPkiMessageSerializerMixin,
        CmpIrMessageSerializerMixin,
        CmpOnboardingAuthenticationMixin,
        CmpOnboardingAuthorizationMixin,
        View):

    http_method_names = ('post', )

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    serialized_ir_message: PkiIrMessage
    requested_domain: DomainModel
    onboarding_process: TrustpointClientOnboardingProcessModel

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:

        requested_subject = self.serialized_ir_message.request_template.subject

        common_name_attributes = requested_subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

        if len(common_name_attributes) != 1:
            return HttpResponse('Wrong requested subject', status=400)

        common_name = common_name_attributes[0].value.strip()
        if common_name.lower() != LocalDomainCredentialIssuer.get_fixed_values(
                device=self.onboarding_process.device,
                domain=self.requested_domain)['common_name'].lower():
            return HttpResponse('The common name in the request must match the default value.', status=400)
        local_domain_credential_issuer = LocalDomainCredentialIssuer(
            device=self.onboarding_process.device,
            domain=self.requested_domain)
        new_domain_credential = local_domain_credential_issuer.issue_domain_credential()
        self.onboarding_process.delete()
        self.device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
        self.device.save()

        response_message = rfc4210.PKIMessage()

        # domain_credential_issuer = LocalDomainCredentialIssuer(domain=self.domain, device=self.device)

        # Get certificate request parameters.
        # Check certificate request parameters -> further authorization.
        # Execute operation.

        return HttpResponse('hello', status=200)
