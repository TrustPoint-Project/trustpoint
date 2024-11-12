"""API endpoints for the onboarding app."""


from __future__ import annotations

import base64
import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from pki.util.keys import SignatureSuite, DigitalSignature

from devices.models import Device
from django.http import HttpRequest, HttpResponse
from ninja import Router, Schema
from ninja.responses import Response, codes_4xx
from pathlib import Path

from onboarding.crypto_backend import CryptoBackend as Crypt
from onboarding.crypto_backend import VerificationError, OnboardingError
from onboarding.models import (
    DownloadOnboardingProcess,
    ManualOnboardingProcess,
    AokiOnboardingProcess,
    OnboardingProcess,
    OnboardingProcessState,
)
from pki.oid import PublicKeyAlgorithmOid, EllipticCurveOid
from trustpoint.schema import ErrorSchema, SuccessSchema
from onboarding.schema import (
    AokiInitMessageSchema,
    AokiInitResponseSchema,
    AokiFinalizationMessageSchema,
    AokiFinalizationResponseSchema
)
from pki import ReasonCode
from pki.models import CertificateModel, TrustStoreModel, DomainModel

log = logging.getLogger('tp.onboarding')

router = Router()

class RawFileSchema(Schema):
    """Wildcard schema, works for arbitrary content."""

def _get_signature_suite_from_ca_type(issuing_ca_cert: CertificateModel) -> SignatureSuite:
    if issuing_ca_cert.spki_algorithm_oid == PublicKeyAlgorithmOid.RSA.value:
        if issuing_ca_cert.spki_key_size == 2048:
            return SignatureSuite.RSA2048
        elif issuing_ca_cert.spki_key_size == 3072:
            return SignatureSuite.RSA3072
        elif issuing_ca_cert.spki_key_size == 4096:
            return SignatureSuite.RSA4096
        else:
            raise ValueError
    elif issuing_ca_cert.spki_algorithm_oid == PublicKeyAlgorithmOid.ECC.value:
        if issuing_ca_cert.spki_ec_curve_oid == EllipticCurveOid.SECP256R1.value:
            return SignatureSuite.SECP256R1
        elif issuing_ca_cert.spki_ec_curve_oid == EllipticCurveOid.SECP384R1.value:
            return SignatureSuite.SECP384R1
        else:
            raise ValueError
    else:
        raise ValueError

# --- PUBLIC ONBOARDING API ENDPOINTS ---

@router.get('/trust-store/{url_ext}', response={200: RawFileSchema, 404: ErrorSchema}, auth=None, exclude_none=True)
def trust_store(request: HttpRequest, url_ext: str) -> tuple[int, dict] | HttpResponse:
    """Returns the trust store for the onboarding process."""
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, {'error': 'Onboarding process not found.'}
    try:
        trust_store_ = Crypt.get_trust_store()
    except FileNotFoundError:
        onboarding_process.fail('Trust store file not found.')
        return 404, {'error': 'Trust store file not found.'}

    issuing_ca_cert = onboarding_process.device.domain.issuing_ca.issuing_ca_certificate
    signature_suite = _get_signature_suite_from_ca_type(issuing_ca_cert)

    response = HttpResponse(trust_store_, status=200, content_type='application/x-pem-file')
    response['hmac-signature'] = onboarding_process.get_hmac()
    response['domain'] = onboarding_process.device.domain.unique_name
    response['signature-suite'] = signature_suite.value
    response['pki-protocol'] = 'CMP'
    response['Content-Disposition'] = 'attachment; filename="tp-trust-store.pem"'
    if onboarding_process.state == OnboardingProcessState.HMAC_GENERATED:
        onboarding_process.state = OnboardingProcessState.TRUST_STORE_SENT
    return response

@router.post('/ldevid/{url_ext}',
             response={200: RawFileSchema, 400: ErrorSchema, 404: ErrorSchema, 500: ErrorSchema},
             auth=None, exclude_none=True)
def ldevid(request: HttpRequest, url_ext: str):
    """Handles the LDevID certificate signing request.

    Inputs:
        Onboarding process URL extension (in request path)

    Returns: LDevID certificate chain (in response body)
    """
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)

    # only ever allow one set of credentials to be submitted
    if (
        not onboarding_process
        or not onboarding_process.active
        or onboarding_process.state >= OnboardingProcessState.DEVICE_VALIDATED
        or not request.FILES
        or not request.FILES['ldevid.csr']
    ):
        return 404, {'error': 'Onboarding process not found.'}

    # get http basic auth header
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2 and auth[0].lower() == 'basic':  # only basic auth is supported # noqa: PLR2004
            uname, passwd = base64.b64decode(auth[1]).decode('us-ascii').split(':')
            if onboarding_process.check_ldevid_auth(uname, passwd):
                csr_file = request.FILES['ldevid.csr']
                if not csr_file or csr_file.multiple_chunks():  # stop client providing a huge file
                    return 400, {'error': 'Invalid CSR.'}
                csr = csr_file.read()
                ldevid = onboarding_process.sign_ldevid(csr)
                if ldevid:
                    response = HttpResponse(ldevid, status=200, content_type='application/x-pem-file')
                    response['Content-Disposition'] = 'attachment; filename="ldevid.pem"'
                    return response

                return 500, {'error': 'Error during certificate creation.'}

            #onboarding_process canceled itself if the client provides incorrect credentials
            return 404, {'error': 'Onboarding process not found.'}

    response = HttpResponse(status=401)
    response['WWW-Authenticate'] = f'Basic realm="{url_ext}"'
    return response

@router.get('/ldevid/cert-chain/{url_ext}',
            response={200: RawFileSchema, 404: ErrorSchema},
            auth=None, exclude_none=True)
def cert_chain(request: HttpRequest, url_ext: str) -> tuple[int, dict] | HttpResponse:
    """Returns the certificate chain of the LDevID certificate."""
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, {'error': 'Onboarding process not found.'}
    cert_chain = onboarding_process.get_cert_chain()
    if not cert_chain:
        return 404, {'error': 'Certificate chain not found.'}

    # could use cryptography.x509.verification to verify the chain,
    # it has just been added in cryptography 42.0.0 and is still marked as an unstable API

    # TODO(Air): do we want to verify the LDevID as a TLS client certificate?
    # This would a) require the LDevID to have extendedKeyUsage=clientAuth and
    #            b) require Nginx/Apache to be configured to handle client certificates
    # Verifying client certificates in Django requires a custom middleware, e.g. django-ssl-auth (unmaintained!)

    response = HttpResponse(cert_chain, status=200, content_type='application/x-pem-file')
    response['Content-Disposition'] = 'attachment; filename="tp-cert-chain.pem"'
    return response

# --- AOKI ZERO TOUCH ONBOARDING API ENDPOINTS ---

AOKI_OWNER_PRIVATE_KEY_PATH = Path(__file__).parent.parent.parent / 'tests/data/aoki_zero_touch/owner_private.key'

@router.post('/aoki/init', response={200: AokiInitResponseSchema, codes_4xx: ErrorSchema}, auth=None, exclude_none=True)
def aoki_init(request: HttpRequest, data: AokiInitMessageSchema):
    """Initializes the AOKI Zero Touch onboarding process."""
    # get request data
    idevid = data.idevid.encode()
    client_nonce = data.client_nonce

    try:
        idevid_cert = x509.load_pem_x509_certificate(idevid)
        idevid_subject_sn = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
    except (ValueError, IndexError):
        return 400, {'error': 'IDevID certificate not parsable.'}
    # verify IDevID against chains of trust stored in Trust stores
    # TODO (Air): extra trust store in Trustpoint for IDevID verification?
    log.warning('AokiInit: IDevID verification not fully implemented.')
    idevid_cert_serial = format(idevid_cert.serial_number, 'X')
    log.debug(f'AokiInit: IDevID: {idevid_cert.subject} SN: {idevid_cert_serial}')
    # TODO (Air): Chain validation so that actual cert is not required in TS, only the root
    idevid_cert_db = None
    # TODO (Air): This loop is horribly inefficient
    # consider adding a field to TrustStoreModel to store if an entry is for IDevID verification
    for ts in TrustStoreModel.objects.all():
        try:
            idevid_cert_db = ts.certificates.get(serial_number=idevid_cert_serial)
            break
        except CertificateModel.DoesNotExist:
            pass

    if not idevid_cert_db:
        return 403, {'error': 'Unauthorized.'}

    # TODO (Air): Even more inefficient
    ownership_cert = None
    for ts in TrustStoreModel.objects.all():
        for cert in ts.certificates.all():
            candidate : x509.Certificate = cert.get_certificate_serializer().as_crypto()
            dc_attr = candidate.subject.get_attributes_for_oid(x509.NameOID.DOMAIN_COMPONENT)
            serial_attr = candidate.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
            
            if (dc_attr and serial_attr
                and dc_attr[0].value == 'Owner'
                and serial_attr[0].value == idevid_subject_sn):
                ownership_cert = candidate
                break

    if not ownership_cert:
        return 404, {'error': 'Not found.'}
    
    aoki_device = Device.objects.filter(device_serial_number=idevid_subject_sn).first()

    if aoki_device:
        log.warning(f'Onboarding existing AOKI device {aoki_device.pk} ({idevid_subject_sn})!')
        aoki_device.revoke_ldevid(ReasonCode.SUPERSEDED)
    else:
        aoki_device = Device(
            device_name=f'AOKI{idevid_subject_sn}', # temporary name until we know PK
            device_serial_number=idevid_subject_sn,
            onboarding_protocol=Device.OnboardingProtocol.AOKI
        )
        # TODO (Air): set proper domain (this must be configurable per ownership certificate)
        aoki_device.domain = DomainModel.objects.first()
        aoki_device.save() # save to get PK assigned
        aoki_device.device_name = f'AOKI_Device_{aoki_device.pk}'
        aoki_device.save()
    
    onboarding_process = OnboardingProcess.make_onboarding_process(aoki_device, AokiOnboardingProcess)
    onboarding_process.set_idevid_cert(idevid)

    # TODO (Air): get the private key for the ownership certificate
    try:
        with AOKI_OWNER_PRIVATE_KEY_PATH.open('rb') as keyfile:
            ownership_private_key = serialization.load_pem_private_key(keyfile.read(), password=None)
    except (FileNotFoundError, ValueError):
        log.exception('Could not load owner private key.', exc_info=True)
        return 404, {'error': 'Not found.'}  # Technically an accurate error message, but we don't give too much away

    response = {
        'ownership_cert': ownership_cert.public_bytes(serialization.Encoding.PEM).decode(),
        'server_nonce': onboarding_process.get_server_nonce(),
        'client_nonce': client_nonce,
        'server_tls_cert': Crypt.get_server_tls_cert(),	
    }
    response_bytes = str(response).encode()
    # hash = hashes.Hash(hashes.SHA256())
    # hash.update(response_bytes)
    # log.debug(f'SHA-256 hash of message: {hash.finalize().hex()}')
    server_signature = DigitalSignature.sign(data=response_bytes, private_key=ownership_private_key)
    #server_signature = ownership_private_key.sign(data=response_bytes, signature_algorithm=server_signature_suite.value)
    print(server_signature)
    server_signature = base64.b64encode(server_signature).decode()
    print(f'Server signature: {server_signature}')
    print(f'Signer public key: {ownership_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}')
    return Response(response, status=200, headers={'aoki-server-signature': server_signature})


@router.post('/aoki/finalize', response={200: AokiFinalizationResponseSchema, 404: ErrorSchema}, auth=None, exclude_none=True)
def aoki_finalize(request: HttpRequest, data: AokiFinalizationMessageSchema):
    """Finalizes the AOKI Zero Touch onboarding process."""

    try:
        client_signature = base64.b64decode(request.headers['aoki-client-signature'].encode('utf-8'))
    except KeyError:
        return 400, {'error': 'No.'}
    
    server_nonce = data.server_nonce
    onboarding_process = AokiOnboardingProcess.get_by_nonce(server_nonce)
    if not onboarding_process:
        return 404, {'error': 'Not found.'}
    
    data_bytes = data.model_dump_json().encode()

    try:
        onboarding_process.verify_client_signature(data_bytes, client_signature)
    except (VerificationError, InvalidSignature, OnboardingError):
        log.debug('AOKI client signature verification failed.')
        return 404, {'error': 'Not found.'}
    
    log.debug('AOKI client signature verified successfully.')

    issuing_ca_cert = onboarding_process.device.domain.issuing_ca.issuing_ca_certificate
    signature_suite = _get_signature_suite_from_ca_type(issuing_ca_cert)
    
    response = {
        'otp': onboarding_process.otp,
        'device': onboarding_process.device.device_name,
        'domain': onboarding_process.device.domain.unique_name,
        'signature_suite': signature_suite.value,
        'pki_protocol': 'CMP'
    }
    
    return 200, response
    

# --- ONBOARDING MANAGEMENT API ENDPOINTS ---

@router.get('/state/{url_ext}', response={200: int, 404: int}, auth=None)
def state(request: HttpRequest, url_ext: str):
    """Returns the state of the onboarding process as an int."""
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, OnboardingProcessState.NO_SUCH_PROCESS
    return 200, onboarding_process.state

@router.post('/{device_id}')
def start(request: HttpRequest, device_id: int) -> tuple[int, dict] | HttpResponse:
    """Starts the onboarding process for a device.

    Restarts if already onboarded. Does nothing if process already running.

    Returns a JSON object with the secrets required for the onboarding process.
    An exception is the manual P12 download onboarding type, which will return the PKCS#12 file.
    """
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}

    ok, msg = Device.check_onboarding_prerequisites(device_id,
                [Device.OnboardingProtocol.CLI,
                 Device.OnboardingProtocol.TP_CLIENT,
                 Device.OnboardingProtocol.MANUAL])

    if not ok:
        return 422, {'error': msg}

    if (device.onboarding_protocol == Device.OnboardingProtocol.MANUAL):
        onboarding_process = OnboardingProcess.make_onboarding_process(device, DownloadOnboardingProcess)
        response = HttpResponse(onboarding_process.get_pkcs12(), status=200, content_type='application/x-pkcs12')
        response['Content-Disposition'] = f'attachment; filename="{device.device_serial_number}.p12"'
        onboarding_process.cancel()
        return response

    onboarding_process = OnboardingProcess.make_onboarding_process(device, ManualOnboardingProcess)
    properties = {
        'otp': onboarding_process.otp,
        'salt': onboarding_process.salt,
        'tsotp': onboarding_process.tsotp,
        'tssalt': onboarding_process.tssalt,
        'host': request.get_host(),
        'url': onboarding_process.url,
        'device': {
            'name': device.device_name,
            'id': device.id,
            'sn': device.device_serial_number,
        }
    }
    return 200, properties


@router.delete('/{device_id}', response={200: SuccessSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def stop(request: HttpRequest, device_id: int) -> tuple[int, dict] | HttpResponse:
    """Stops and removes the onboarding process for a device.

    Cancels the process if it is running.
    """
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}

    state, onboarding_process = OnboardingProcess.cancel_for_device(device)

    if state == OnboardingProcessState.COMPLETED:
        return 200, {'success':True, 'message': f'Device {device.device_name} onboarded successfully.'}
    if state == OnboardingProcessState.FAILED:
        reason = onboarding_process.error_reason if onboarding_process else ''
        return 422, {'error': f'Onboarding process for device {device.device_name} failed.', 'detail': reason}
    if state == OnboardingProcessState.CANCELED:
        return 200, {'success':True, 'message': f'Onboarding process for device {device.device_name} canceled.'}
    if state != OnboardingProcessState.NO_SUCH_PROCESS:
        return 422, {'error': f'Onboarding process for device {device.device_name} is in unexpected state {state}.'}

    return 404, {'error': f'No active onboarding process for device {device.device_name} found.'}

@router.post('/revoke/{device_id}',
             response={200: SuccessSchema, 404: ErrorSchema, 422: ErrorSchema},
             exclude_none=True)
def revoke(request: HttpRequest, device_id: int) -> tuple[int, dict] | HttpResponse:
    """Revokes the LDevID certificate for a device."""
    # TODO (Air): The API should include the possibility to specify the revocation reason
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}

    if device.ldevid:
        if device.revoke_ldevid(ReasonCode.CESSATION):
            return 200, {'success': True}
        return 422, {'error': 'Error during certificate revocation.'}
    return 422, {'error': 'Device has no LDevID certificate to revoke.'}
