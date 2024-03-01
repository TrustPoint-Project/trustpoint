"""Module that implements all views corresponding to the Onboarding application."""

from __future__ import annotations
from typing import TYPE_CHECKING

import base64

from devices.models import Device
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import RedirectView

from .crypto_backend import CryptoBackend as Crypt
from .forms import OnboardingStartForm
from .models import OnboardingProcess, OnboardingProcessState, onboarding_processes

if TYPE_CHECKING:
    from django.http import HttpRequest

class IndexView(RedirectView):
    """Redirects requests to /index to the manual onboarding page."""

    permanent = False
    pattern_name = 'onboarding:manual'


def onboarding_manual(request: HttpRequest) -> HttpResponse:
    """View for the manual onboarding page."""
    context = {'page_category': 'onboarding', 'page_name': 'manual'}

    # TODO(Air): create decorator for unexpected exception handling
    if request.method == 'POST' and 'onboarding-start-form' in request.POST:
        onboarding_start_form = OnboardingStartForm(request.POST, request.FILES)

        if onboarding_start_form.is_valid():
            name = onboarding_start_form.cleaned_data.get('name')

            device = Device(
                device_name=name,
                onboarding_protocol=Device.OnboardingProtocol.CLIENT,
            )
            device.save()

            p = OnboardingProcess(device)
            onboarding_processes.append(p)

            return redirect('onboarding:manual-client',device_id=device.id)

    context['onboarding_start_form'] = OnboardingStartForm()

    return render(request, 'onboarding/manual.html', context=context)


def onboarding_manual_client(request: HttpRequest, device_id: int) -> HttpResponse:
    """View for the manual onboarding with Trustpoint client (cli command and status display) page."""

    device = Device.get_by_id(device_id)
    if not device:
        messages.error(request, f'Onboarding: Device with ID {device_id} not found.')
        return redirect('devices:devices')
    
    # choose the onboarding method for this device
    if device.onboarding_protocol != Device.OnboardingProtocol.CLIENT:
        label = Device.OnboardingProtocol(device.onboarding_protocol).label
        messages.error(request, f'Onboarding protocol {label} is not implemented.')
        return redirect('devices:devices')
    
    # check that endpoint profile is set
    if not device.endpoint_profile:
        messages.error(
            request,
            f'Onboarding: Please select an endpoint profile for device {device.device_name} first.')
        return redirect('devices:devices')
    
    # TODO(Air): check that device is not already onboarded
    # Re-onboarding might be a valid use case, e.g. to renew a certificate
    
    # check if onboarding process for this device already exists
    onboarding_process = OnboardingProcess.get_by_device(device)

    if not onboarding_process:
        onboarding_process = OnboardingProcess(device)
        onboarding_processes.append(onboarding_process)
        device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDING_RUNNING
        # TODO(Air): very unnecessary save required to update onboarding status in table
        # Problem: if server is restarted during onboarding, status is stuck at running
        device.save()

    context = {
        'page_category': 'onboarding',
        'page_name': 'manual',
        'otp':onboarding_process.otp,
        'salt':onboarding_process.salt,
        'tsotp':onboarding_process.tsotp,
        'tssalt':onboarding_process.tssalt,
        'tpurl': request.get_host,
        'url':onboarding_process.url,
        'device_name':onboarding_process.device.device_name,
        'device_id':onboarding_process.device.id,
    }
    return render(request, 'onboarding/manual/client.html', context=context)


def onboarding_cancel(request: HttpRequest, device_id: int) -> HttpResponse:
    """View for the onboarding cancel page."""
    device = Device.get_by_id(device_id)
    if not device:
        messages.error(request, f'Onboarding: Device with ID {device_id} not found.')
        return redirect('devices:devices')
    
    onboarding_process = OnboardingProcess.get_by_device(device)
    if not onboarding_process:
        messages.error(request, f'No active onboarding process for device {device.device_name}.')
        return redirect('devices:devices')

    onboarding_process._fail('Onboarding process canceled by user.')
    onboarding_processes.remove(onboarding_process)

    # This is an attempt to handle race conditions (e.g. cancel pressed after onboarding completed)
    if device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
        device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
        device.save()
        messages.warning(request, f'Onboarding process for device {device.device_name} canceled.')
    else:
        messages.warning(request,
                         f'Did not cancel onboarding process for {device.device_name} as it was not running.')

    return redirect('devices:devices')


def onboarding_exit(request: HttpRequest, device_id: int) -> HttpResponse:
    """Cancels onboarding if still running, injects a message and redirects to the devices page."""

    device = Device.get_by_id(device_id)
    if not device:
        messages.error(request, f'Onboarding: Device with ID {device_id} not found.')
        return redirect('devices:devices')
    
    onboarding_process = OnboardingProcess.get_by_device(device)
    if not onboarding_process:
        messages.error(request, f'No active onboarding process for device {device.device_name}.')
        return redirect('devices:devices')

    reason = onboarding_process.error_reason
    # TODO(Air): We also need to remove the onboarding process automatically without calling this view
    onboarding_processes.remove(onboarding_process)
    if onboarding_process.state == OnboardingProcessState.COMPLETED:
        messages.success(request, f'Device {device.device_name} onboarded successfully.')
    elif onboarding_process.state == OnboardingProcessState.FAILED:
        messages.error(request, f'Onboarding process for device {device.device_name} failed. {reason}')
        # TODO(Air): what to do if timeout occurs after valid LDevID is issued?
        # TODO(Air): Delete device and add to CRL.
    else:
        if device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
            device.save()
            messages.warning(request, f'Onboarding process for device {device.device_name} canceled.')
        else:
            messages.warning(request,
                             f'Did not cancel onboarding process for {device.device_name} as it was not running.')

    return redirect('devices:devices')


def trust_store(request: HttpRequest, test: str) -> HttpResponse:
    """View for the trust store API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns:
        Trust store (in response body)
        HMAC signature of trust store (in response header)
    """
    # get URL extension
    url_extension = test
    onboarding_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not onboarding_process or not onboarding_process.active:
        return HttpResponse('Invalid URI extension.', status=404)

    try:
        trust_store = Crypt.get_trust_store()
    except FileNotFoundError:
        onboarding_process.fail('Trust store file not found.')
        return HttpResponse('Trust store file not found.', status=500)

    response = HttpResponse(trust_store, status=200)
    response['hmac-signature'] =onboarding_process.get_hmac()
    if onboarding_process.state == OnboardingProcessState.HMAC_GENERATED:
       onboarding_process.state = OnboardingProcessState.TRUST_STORE_SENT
    return response


@csrf_exempt  # should be safe because we are using a OTP
def ldevid(request: HttpRequest) -> HttpResponse:
    """View for the LDevID API endpoint.

    Request type: POST

    Inputs:
        Onbarding process URL extension (in request path)
        Certificate signing request (as POST file ldevid.csr)

    Returns: LDevID certificate chain (in response body)
    """
    # get URL extension
    url_extension = request.path.split('/')[-1]
    onboarding_process = OnboardingProcess.get_by_url_ext(url_extension)
    if (
        not onboarding_process
        or not onboarding_process.active
        # only ever allow one set of credentials to be submitted
        or onboarding_process.state >= OnboardingProcessState.DEVICE_VALIDATED
        or request.method != 'POST'
        or not request.FILES
        or not request.FILES['ldevid.csr']
    ):
        return HttpResponse('Invalid URI extension.', status=404)

    # get http basic auth header
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2 and auth[0].lower() == 'basic':  # only basic auth is supported # noqa: PLR2004
            uname, passwd = base64.b64decode(auth[1]).decode('us-ascii').split(':')
            if onboarding_process.check_ldevid_auth(uname, passwd):
                csr_file = request.FILES['ldevid.csr']
                if not csr_file or csr_file.multiple_chunks():  # stop client providing a huge file
                    return HttpResponse('Invalid CSR.', status=400)
                csr = csr_file.read()
                ldevid =onboarding_process.sign_ldevid(csr)
                if ldevid:
                    return HttpResponse(ldevid, status=200)

                return HttpResponse('Error during certificate creation.', status=500)

            #onboarding_process canceled itself if the client provides incorrect credentials
            return HttpResponse('Invalid URI extension.', status=404)

    response = HttpResponse(status=401)
    response['WWW-Authenticate'] = 'Basic realm="%s"' % url_extension
    return response


def cert_chain(request: HttpRequest) -> HttpResponse:
    """View for the LDevID certificate chain API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns: LDevID certificate chain (in response body)

    TODO: instead of URL extension, match using the client LDevID certificate
    TODO: chain with or without end-entity certificate?
    """
    # get URL extension
    url_extension = request.path.split('/')[-1]
    onboarding_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not onboarding_process or not onboarding_process.active:
        return HttpResponse('Invalid URI extension.', status=404)

    # could use cryptography.x509.verification to verify the chain,
    # it has just been added in cryptography 42.0.0 and is still marked as an unstable API

    # TODO(Air): do we want to verify the LDevID as a TLS client certificate?
    # This would a) require the LDevID to have extendedKeyUsage=clientAuth and
    #            b) require Nginx/Apache to be configured to handle client certificates
    # Verifying client certificates in Django requires a custom middleware, e.g. django-ssl-auth, which is unmaintained

    chain = onboarding_process.get_cert_chain()
    if chain:
        return HttpResponse(chain, status=200)
    return HttpResponse('Invalid URI extension.', status=404)

def state(request: HttpRequest) -> HttpResponse:
    """View for the onboarding process state API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns: Onboarding process state as an integer (representing OnboardingProcessState enum, in response body)
    """
    # get URL extension
    url_extension = request.path.split('/')[-1]
    onboarding_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not onboarding_process:
        return HttpResponse(str(OnboardingProcessState.NO_SUCH_PROCESS), status=404)

    return HttpResponse(str(onboarding_process.state), status=200)
