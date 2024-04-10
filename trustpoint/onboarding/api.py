import base64

from ninja import Router, Schema
from ninja.security import django_auth
from django.http import HttpRequest, HttpResponse
from trustpoint.schema import ErrorSchema, SuccessSchema
from devices.models import Device
from onboarding.models import OnboardingProcess, OnboardingProcessState, DownloadOnboardingProcess, ManualOnboardingProcess
from onboarding.crypto_backend import CryptoBackend as Crypt

router = Router()

class RawFileSchema(Schema):
    """"Wildcard schema, works for arbitrary content."""
    pass

# --- PUBLIC ONBOARDING API ENDPOINTS ---

@router.get("/trust-store/{url_ext}", response={200: RawFileSchema, 404: ErrorSchema}, auth=None, exclude_none=True)
def trust_store(request: HttpRequest, url_ext: str) -> HttpResponse:
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, {'error': 'Onboarding process not found.'}
    try:
        trust_store = Crypt.get_trust_store()
    except FileNotFoundError:
        onboarding_process.fail('Trust store file not found.')
        return 404, {'error': 'Trust store file not found.'}
        return HttpResponse('Trust store file not found.', status=500)

    response = HttpResponse(trust_store, status=200, content_type='application/x-pem-file')
    response['hmac-signature'] = onboarding_process.get_hmac()
    response['Content-Disposition'] = 'attachment; filename="tp-trust-store.pem"'
    if onboarding_process.state == OnboardingProcessState.HMAC_GENERATED:
        onboarding_process.state = OnboardingProcessState.TRUST_STORE_SENT
    return response

@router.post("/ldevid/{url_ext}", response={200: RawFileSchema, 400: ErrorSchema, 404: ErrorSchema, 500: ErrorSchema}, auth=None, exclude_none=True)
def ldevid(request: HttpRequest, url_ext: str):
    """Handles the LDevID certificate signing request.

    Inputs:
        Onbarding process URL extension (in request path)

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
    response['WWW-Authenticate'] = 'Basic realm="%s"' % url_ext
    return response

@router.get("/ldevid/cert-chain/{url_ext}", response={200: RawFileSchema, 404: ErrorSchema}, auth=None, exclude_none=True)
def cert_chain(request: HttpRequest, url_ext: str):
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

# --- ONBOARDING MANAGEMENT API ENDPOINTS ---

@router.get("/state/{url_ext}", response={200: int, 404: int})
def state(request: HttpRequest, url_ext: str):
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, OnboardingProcessState.NO_SUCH_PROCESS
    return 200, onboarding_process.state

@router.post("/{device_id}")
def start(request: HttpRequest, device_id: int):
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
        response['Content-Disposition'] = f'attachment; filename="{device.serial_number}.p12"'
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
            'sn': device.serial_number,
        }
    }
    return 200, properties


@router.delete("/{device_id}", response={200: SuccessSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def stop(request: HttpRequest, device_id: int):
    """Stops and removes the onboarding process for a device.
    
    Cancels the process if it is running.
    """
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}
    
    state, onboarding_process = OnboardingProcess.cancel_for_device(device)

    if state == OnboardingProcessState.COMPLETED:
        return 200, {'success':True, 'message': f'Device {device.device_name} onboarded successfully.'}
    elif state == OnboardingProcessState.FAILED:
        # TODO(Air): what to do if timeout occurs after valid LDevID is issued?
        # TODO(Air): Delete device and add to CRL.
        reason = onboarding_process.error_reason if onboarding_process else ''
        return 422, {'error': f'Onboarding process for device {device.device_name} failed.', 'detail': reason}
    elif state == OnboardingProcessState.CANCELED:
        return 200, {'success':True, 'message': f'Onboarding process for device {device.device_name} canceled.'}
    elif state != OnboardingProcessState.NO_SUCH_PROCESS:
        return 422, {'error': f'Onboarding process for device {device.device_name} is in unexpected state {state}.'}

    if not onboarding_process:
        return 404, {'error': f'No active onboarding process for device {device.device_name} found.'}

@router.post("/revoke/{device_id}", response={200: SuccessSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def revoke(request: HttpRequest, device_id: int):
    """Revokes the LDevID certificate for a device."""
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}
    
    if device.revoke_ldevid():
        return 200, {'success': True}
    return 422, {'error': 'Device has no LDevID certificate to revoke.'}
