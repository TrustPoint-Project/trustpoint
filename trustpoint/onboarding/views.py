"""Module that implements all views corresponding to the Onboarding application."""


import base64

from devices.models import Device
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import RedirectView

from .crypto_backend import CryptoBackend as Crypt
from .forms import OnboardingStartForm
from .models import OnboardingProcess, OnboardingProcessState, onboarding_processes


class IndexView(RedirectView):
    """Redirects requests to /index to the manual onboarding page."""

    # Permanent redirects require clearing browser cache to change, only use if we know the redirect will never change
    permanent = True
    pattern_name = 'onboarding:manual'


def onboarding_manual(request: HttpRequest) -> HttpResponse:
    """View for the manual onboarding page."""
    context = {'page_category': 'onboarding', 'page_name': 'manual'}

    # remove any existing onboarding process from session
    ob_process = None
    if 'onboarding_process_id' in request.session:
        ob_process = OnboardingProcess.get_by_id(request.session['onboarding_process_id'])
        if ob_process:
            device = ob_process.device.name
            reason = ob_process.error_reason
            onboarding_processes.remove(ob_process)
            if ob_process.state == OnboardingProcessState.COMPLETED:
                messages.success(request, f'Device {device} onboarded successfully.')
            elif ob_process.state == OnboardingProcessState.FAILED:
                messages.error(request, f'Onboarding process for device {device} failed. {reason}')
                # TODO(Air): what to do if timeout occurs after valid LDevID is issued?
                # TODO(Air): Consider that a successful onboarding? Alternatively delete device and add to CRL.
            else:
                messages.warning(request, f'Onboarding process for device {device} canceled.')
        del request.session['onboarding_process_id']

    # TODO(Air): create decorator for unexpected exception handling
    if request.method == 'POST' and 'onboarding-start-form' in request.POST:
        onboarding_start_form = OnboardingStartForm(request.POST, request.FILES)

        if onboarding_start_form.is_valid():
            name = onboarding_start_form.cleaned_data.get('name')

            onboarding_device = Device(
                name=name,
            )

            p = OnboardingProcess(onboarding_device)
            onboarding_processes.append(p)
            request.session['onboarding_process_id'] = p.id

            # TODO(Air): error handling
            # onboarding_device.save()

            return redirect('onboarding:manual-client')

    context['onboarding_start_form'] = OnboardingStartForm()

    return render(request, 'onboarding/manual.html', context=context)


def onboarding_manual_client(request: HttpRequest) -> HttpResponse:
    """View for the manual onboarding with Trustpoint client (cli command and status display) page."""
    process_id = None
    ob_process = None
    if 'onboarding_process_id' in request.session:
        process_id = request.session['onboarding_process_id']
    else:
        messages.error(request, 'No onboarding process found in session.')
        return redirect('onboarding:manual')

    ob_process = OnboardingProcess.get_by_id(process_id)
    if not ob_process:
        messages.error(request, f'Onboarding process with ID {process_id} not found.')
        return redirect('onboarding:manual')

    context = {
        'page_category': 'onboarding',
        'page_name': 'manual',
        'otp': ob_process.otp,
        'salt': ob_process.salt,
        'tsotp': ob_process.tsotp,
        'tssalt': ob_process.tssalt,
        'tpurl': request.get_host,
        'url': ob_process.url,
        'device_name': ob_process.device.name,
    }
    return render(request, 'onboarding/manual/client.html', context=context)


def trust_store(request: HttpRequest) -> HttpResponse:
    """View for the trust store API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns:
        Trust store (in response body)
        HMAC signature of trust store (in response header)
    """
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process or not ob_process.active:
        return HttpResponse('Invalid URI extension.', status=404)

    try:
        trust_store = Crypt.get_trust_store()
    except FileNotFoundError:
        ob_process.fail('Trust store file not found.')
        return HttpResponse('Trust store file not found.', status=500)

    response = HttpResponse(trust_store, status=200)
    response['hmac-signature'] = ob_process.get_hmac()
    if ob_process.state == OnboardingProcessState.HMAC_GENERATED:
        ob_process.state = OnboardingProcessState.TRUST_STORE_SENT
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
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if (
        not ob_process
        or not ob_process.active
        # only ever allow one set of credentials to be submitted
        or ob_process.state >= OnboardingProcessState.DEVICE_VALIDATED
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
            if ob_process.check_ldevid_auth(uname, passwd):
                csr_file = request.FILES['ldevid.csr']
                if not csr_file or csr_file.multiple_chunks():  # stop client providing a huge file
                    return HttpResponse('Invalid CSR.', status=400)
                csr = csr_file.read()
                ldevid = ob_process.sign_ldevid(csr)
                if ldevid:
                    return HttpResponse(ldevid, status=200)

                return HttpResponse('Error during certificate creation.', status=500)

            # ob_process canceled itself if the client provides incorrect credentials
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
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process or not ob_process.active:
        return HttpResponse('Invalid URI extension.', status=404)

    # could use cryptography.x509.verification to verify the chain,
    # it has just been added in cryptography 42.0.0 and is still marked as an unstable API

    # TODO(Air): do we want to verify the LDevID as a TLS client certificate?
    # This would a) require the LDevID to have extendedKeyUsage=clientAuth and
    #            b) require Nginx/Apache to be configured to handle client certificates
    # Verifying client certificates in Django requires a custom middleware, e.g. django-ssl-auth, which is unmaintained

    response = HttpResponse(Crypt.get_cert_chain(), status=200)
    if ob_process.state == OnboardingProcessState.LDEVID_SENT:
        ob_process.state = OnboardingProcessState.COMPLETED
    return response


def state(request: HttpRequest) -> HttpResponse:
    """View for the onboarding process state API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns: Onboarding process state as an integer (representing OnboardingProcessState enum, in response body)
    """
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process:
        return HttpResponse(str(OnboardingProcessState.NO_SUCH_PROCESS), status=404)

    return HttpResponse(str(ob_process.state), status=200)
