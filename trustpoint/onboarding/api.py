import base64

from ninja import Router, Schema
from ninja.security import django_auth
from django.http import HttpRequest, HttpResponse
from devices.models import Device
from onboarding.models import OnboardingProcess, OnboardingProcessState
from onboarding.crypto_backend import CryptoBackend as Crypt

router = Router(auth=django_auth)

class RawFileSchema(Schema):
    """"Wildcard schema, works for arbitrary content."""
    pass

class ErrorSchema(Schema):
    error: str

# --- PUBLIC ONBOARDING API ENDPOINTS ---

@router.get("/trust-store/{url_ext}", response={200: RawFileSchema, 404: ErrorSchema}, auth=None)
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

@router.post("/ldevid/{url_ext}", response={200: RawFileSchema, 400: ErrorSchema, 404: ErrorSchema, 500: ErrorSchema}, auth=None)
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

@router.get("/ldevid/cert-chain/{url_ext}", response={200: RawFileSchema, 404: ErrorSchema}, auth=None)
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

@router.get("/state/{url_ext}", response={200: int, 404: ErrorSchema})
def state(request: HttpRequest, url_ext: str):
    onboarding_process = OnboardingProcess.get_by_url_ext(url_ext)
    if not onboarding_process:
        return 404, {'error': 'Onboarding process not found.'}
    return onboarding_process.state

@router.post("/{device_id}")
def start(request: HttpRequest, device_id: int):
    """Starts the onboarding process for a device.
    
    Restarts if already onboarded. Does nothing if process already running.

    Returns a JSON object with the secrets required for the onboarding process.
    An exception is the manual P12 download onboarding type, which will return the PKCS#12 file.
    """
    #onboarding_process = OnboardingProcess.start(device_id)
    #return onboarding_process.url_ext
    pass

@router.delete("/{device_id}")
def stop(request: HttpRequest, device_id: int):
    """Stops and removes the onboarding process for a device.
    
    Cancels the process if it is running.
    """
    pass
    #onboarding_process = OnboardingProcess.get_by_device_id(device_id)
    #if onboarding_process:
    #    onboarding_process.cancel()
    #return 200

@router.post("/revoke/{device_id}")
def revoke(request: HttpRequest, device_id: int):
    """Revokes the LDevID certificate for a device."""
    device = Device.get_by_id(device_id)
    if not device:
        return 404, {'error': 'Device not found.'}
    
    if device.revoke_ldevid():
        return 200, {'success': True}
    return 422, {'error': 'Device has no LDevID certificate to revoke.'}
