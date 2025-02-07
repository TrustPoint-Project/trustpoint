import base64
import ipaddress
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol, cast, Any, Optional, Type

from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7
from django.core.exceptions import ValidationError

from core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from django.contrib.auth import authenticate
from django.http import HttpRequest, HttpResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from core.serializer import CertificateCollectionSerializer
from devices.issuer import LocalDomainCredentialIssuer, LocalTlsServerCredentialIssuer, LocalTlsClientCredentialIssuer
from devices.models import TrustpointClientOnboardingProcessModel, DeviceModel, IssuedCredentialModel
from pki.models import DomainModel

if TYPE_CHECKING:
    from django.http import HttpRequest
    from typing import Any


class Dispatchable(Protocol):
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        ...


class EstAuthenticationMixin:
    """
    Checks for HTTP Basic Authentication before processing the request.
    """

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            response = HttpResponse('Authentication required', status=401)
            response['WWW-Authenticate'] = 'Basic realm="EST"'
            return response

        encoded_credentials = auth_header.split(' ', 1)[1].strip()
        try:
            decoded_bytes = base64.b64decode(encoded_credentials)
            decoded_credentials = decoded_bytes.decode('utf-8')
        except Exception:
            return HttpResponse('Invalid authentication credentials', status=400)

        try:
            username, password = decoded_credentials.split(':', 1)
        except ValueError:
            return HttpResponse('Malformed credentials', status=400)

        user = authenticate(request, username=username, password=password)
        if user is None:
            response = HttpResponse('Invalid credentials', status=401)
            response['WWW-Authenticate'] = 'Basic realm="EST"'
            return response

        request.user = user
        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class EstHttpMixin:
    expected_content_type = 'application/pkcs10'
    max_payload_size = 131072  # max 128 KiByte
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

        transfer_encoding = request.headers.get('Content-Transfer-Encoding', '').lower()
        if transfer_encoding == 'base64':
            try:
                self.raw_message = base64.b64decode(self.raw_message)
            except Exception as e:
                return HttpResponse('Invalid base64 encoding in message.', status=400)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class EstRequestedDomainExtractorMixin:
    requested_domain: DomainModel
    issuing_ca_certificate: x509.Certificate
    signature_suite: SignatureSuite

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        domain_name = cast(str, kwargs.get('domain'))

        try:
            self.requested_domain = DomainModel.objects.get(unique_name=domain_name)
            self.issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
            self.signature_suite = SignatureSuite.from_certificate(self.issuing_ca_certificate)

        except DomainModel.DoesNotExist:
            return HttpResponse('Domain does not exist.', status=404)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class EstRequestedCertTemplateExtractorMixin:
    requested_cert_template_str: str
    allowed_cert_templates = ['tlsserver', 'tlsclient', 'domaincredential']

    cert_template_classes: dict[str, Type] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }
    requested_cert_template_class: LocalTlsServerCredentialIssuer | LocalTlsClientCredentialIssuer | LocalDomainCredentialIssuer

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        cert_template = kwargs.get('certtemplate')

        if cert_template not in self.allowed_cert_templates:
            allowed = ', '.join(self.allowed_cert_templates)
            return HttpResponse(
                f'Invalid or missing cert template. Allowed values are: {allowed}.',
                status=404
            )

        self.requested_cert_template_str = cert_template
        self.requested_cert_template_class = self.cert_template_classes[cert_template]

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class EstPkiMessageSerializerMixin:
    """
    Mixin to handle serialization and deserialization of PKCS#10 certificate signing requests,
    and to generate a DER-encoded certificate response.
    """

    def deserialize_pki_message(self, data: bytes) -> x509.CertificateSigningRequest:
        """
        Deserializes a DER-encoded PKCS#10 certificate signing request into a
        cryptography.x509.CertificateSigningRequest object.

        :param data: DER-encoded PKCS#10 request bytes.
        :return: An x509.CertificateSigningRequest object.
        :raises ValueError: If deserialization fails.
        """
        try:
            csr = x509.load_der_x509_csr(data, default_backend())
        except Exception as e:
            raise ValueError("Failed to deserialize PKCS#10 certificate signing request") from e

        self.verify_csr_signature(csr)
        return csr

    def verify_csr_signature(self, csr: x509.CertificateSigningRequest) -> None:
        """
        Verifies that the CSR's signature is valid by using the public key contained in the CSR.
        Supports RSA, ECDSA, and DSA public keys.
        """
        public_key = csr.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=csr.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(csr.signature_hash_algorithm)
                )
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    algorithm=csr.signature_hash_algorithm
                )
            else:
                raise ValueError("Unsupported public key type for CSR signature verification.")
        except Exception as e:
            raise ValueError("CSR signature verification failed.") from e

class NewDeviceFromCSRMixin:
    """
    Mixin that provides functionality to extract the serial number from an X.509 CSR
    and to retrieve or create a DeviceModel instance based on that serial number.

    This mixin assumes the CSR is already deserialized into a cryptography.x509.CertificateSigningRequest object.
    """

    def extract_serial_number_from_csr(self, csr) -> str:
        """
        Extracts the serial number from the provided CSR's subject.

        Looks for the attribute with OID NameOID.SERIAL_NUMBER.

        :param csr: A cryptography.x509.CertificateSigningRequest instance.
        :return: The serial number as a string.
        :raises ValidationError: If the serial number attribute is not found.
        """
        attributes = csr.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if not attributes:
            raise ValidationError("Serial number not found in CSR subject.")
        return attributes[0].value

    def get_or_create_device_from_csr(self, csr, domain, cert_template) -> DeviceModel:
        """
        Retrieves a DeviceModel instance using the serial number extracted from the provided CSR.
        If a device with that serial number does not exist, a new one is created.

        :param csr: A cryptography.x509.CertificateSigningRequest instance.
        :param domain: The DomainModel instance associated with this device.
        :return: A DeviceModel instance corresponding to the extracted serial number.
        """
        serial_number = self.extract_serial_number_from_csr(csr)

        device = DeviceModel.objects.filter(serial_number=serial_number, domain=domain).first()
        if device:
            return device

        if not domain.auto_create_new_device:
            ValueError('Creating a new device for this domain is permitted')

        if cert_template == 'domaincredential':
            onboarding_protocol = DeviceModel.OnboardingProtocol.CLI
            onboarding_status = DeviceModel.OnboardingStatus.PENDING
        else:
            onboarding_protocol = DeviceModel.OnboardingProtocol.NO_ONBOARDING
            onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING

        device = DeviceModel.objects.create(
            serial_number=serial_number,
            unique_name=f"Device-{serial_number}",
            domain=domain,
            onboarding_protocol=onboarding_protocol,
            onboarding_status=onboarding_status,
        )
        return device


class CredentialIssuanceMixin:
    """
    Mixin to handle issuing credentials based on a given certificate template input.

    Required inputs for the `issue_credential` method:
      - cert_template_str: A string indicating the certificate template type.
          Supported values: 'tlsserver', 'tlsclient', or 'domaincredential'.
      - cert_template_class: The class responsible for issuing the credential.
      - device: The device instance for which the credential is issued.
      - domain: The domain instance used during credential issuance.
      - csr: The certificate signing request (used only for 'domaincredential').

    Additional parameters are used by the specific issuance methods:
      - common_name: Used for 'tlsclient' and 'tlsserver' credentials.
      - validity_days: Used for 'tlsclient' and 'tlsserver' credentials.
      - ipv4_addresses, ipv6_addresses, domain_names: Used for 'tlsserver' credentials.
    """

    cert_template_classes: dict[str, Type] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }

    def extract_details_from_csr(self, csr: x509.CertificateSigningRequest):
        """
        Loads the CSR (x509.CertificateSigningRequest) and extracts the common name,
        IPv4 addresses, IPv6 addresses, DNS names, and public key.
        """
        allowed_subject_oids = {x509.NameOID.COMMON_NAME, x509.NameOID.SERIAL_NUMBER}
        subject_attributes = list(csr.subject)
        for attr in subject_attributes:
            if attr.oid not in allowed_subject_oids:
                raise ValueError(
                    f"Unsupported subject attribute: {attr.oid._name if hasattr(attr.oid, '_name') else attr.oid.dotted_string}"
                )

        common_name_attrs = [attr for attr in subject_attributes if attr.oid == x509.NameOID.COMMON_NAME]
        if not common_name_attrs:
            raise ValueError("CSR subject must contain a Common Name attribute.")
        if len(common_name_attrs) > 1:
            raise ValueError("CSR subject must contain only one Common Name attribute.")
        common_name = common_name_attrs[0].value

        try:
            san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value

            for entry in san:
                if not isinstance(entry, (x509.DNSName, x509.IPAddress)):
                    raise ValueError(f"Unsupported SAN type: {type(entry).__name__}")

            dns_names = san.get_values_for_type(x509.DNSName)
            ip_addresses = san.get_values_for_type(x509.IPAddress)
            ipv4_addresses = []
            ipv6_addresses = []
            for ip in ip_addresses:
                if isinstance(ip, ipaddress.IPv4Address):
                    ipv4_addresses.append(ip)
                elif isinstance(ip, ipaddress.IPv6Address):
                    ipv6_addresses.append(ip)
        except x509.ExtensionNotFound:
            dns_names = []
            ipv4_addresses = []
            ipv6_addresses = []

        public_key = csr.public_key()

        return common_name, ipv4_addresses, ipv6_addresses, dns_names, public_key

    def issue_credential(
            self,
            cert_template_str: str,
            device: DeviceModel,
            domain: DomainModel,
            csr: x509.CertificateSigningRequest,
            validity_days: int = 365
    ):

        common_name, ipv4_addresses, ipv6_addresses, dns_names, public_key = self.extract_details_from_csr(csr)

        cert_template_class = self.cert_template_classes[cert_template_str]
        issuer_instance = cert_template_class(device=device, domain=domain)

        # Call the appropriate issuance method based on the certificate template.
        if cert_template_str == 'domaincredential':

            if common_name != 'Trustpoint Domain Credential':
                raise ValueError('Domain Credentials must use the Common Name >Trustpoint Domain Credential<')
            issued_credential = issuer_instance.issue_domain_credential(public_key=public_key)

        elif cert_template_str == 'tlsclient':
            issued_credential = issuer_instance.issue_tls_client_credential(
                common_name=common_name,
                validity_days=validity_days
            )

        elif cert_template_str == 'tlsserver':
            issued_credential = issuer_instance.issue_tls_server_credential(
                common_name=common_name,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                domain_names=dns_names,
                validity_days=validity_days
            )
        else:
            raise ValueError(f"Unsupported certificate template: {cert_template_str}")

        return issued_credential


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(EstAuthenticationMixin,
                              EstHttpMixin,
                              EstRequestedDomainExtractorMixin,
                              EstRequestedCertTemplateExtractorMixin,
                              EstPkiMessageSerializerMixin,
                              NewDeviceFromCSRMixin,
                              CredentialIssuanceMixin,
                              View):
    onboarding_process: None | TrustpointClientOnboardingProcessModel
    device: DeviceModel
    requested_domain: DomainModel
    requested_cert_template_str: str
    issued_credential: IssuedCredentialModel

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            csr = self.deserialize_pki_message(self.raw_message)
        except ValueError as e:
            return HttpResponse(f"Invalid PKCS#10 request: {str(e)}", status=400)

        try:
            device = self.get_or_create_device_from_csr(csr, self.requested_domain, self.requested_cert_template_str)
        except Exception as e:
            return HttpResponse(f'Device lookup/creation error: {str(e)}', status=400)

        try:
            issued_credential = self.issue_credential(cert_template_str=self.requested_cert_template_str,
            device=device,
            domain=self.requested_domain,
            csr=csr)
        except Exception as e:
            return HttpResponse(f'Error while issuing credential: {str(e)}', status=400)

        encoded_cert = issued_credential.credential.get_certificate().public_bytes(
            encoding=Encoding.DER)

        issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
        raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()

        certificate_chain = [
                                self.requested_domain.issuing_ca.credential.get_certificate()
                            ] + self.requested_domain.issuing_ca.credential.get_certificate_chain()

        return HttpResponse(encoded_cert, status=200, content_type="application/pkix-cert")


@method_decorator(csrf_exempt, name="dispatch")
class EstCACertsView(EstAuthenticationMixin, EstRequestedDomainExtractorMixin, View):
    """
    View to handle the EST /cacerts endpoint.
    Returns the CA certificate chain in a (simplified) PKCS#7 MIME format.

    URL pattern should supply the 'domain' parameter (e.g., /cacerts/<domain>/)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            ca_credential = self.requested_domain.issuing_ca.credential

            ca_cert = ca_credential.get_certificate()
            certificate_chain = [ca_cert] + ca_credential.get_certificate_chain()

            pkcs7_certs = CertificateCollectionSerializer(certificate_chain).as_pkcs7_der()

            pkcs7_certs_b64 = base64.b64encode(pkcs7_certs)

            return HttpResponse(
                pkcs7_certs_b64,
                status=200,
                content_type="application/pkcs7-mime",
                headers={"Content-Transfer-Encoding": "base64"}
            )
        except Exception as e:
            print(e)
            return HttpResponse(
                f"Error retrieving CA certificates: {str(e)}", status=500
            )