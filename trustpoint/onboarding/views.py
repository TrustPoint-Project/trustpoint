from django.shortcuts import render, redirect
from .forms import OnboardingStartForm
from devices.models import Device
from django.http import HttpResponse
from django.views.generic.base import RedirectView
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import OnboardingProcess, onboardingProcesses, OnboardingProcessState
from .cryptoBackend import CryptoBackend as Crypt
import base64


class IndexView(RedirectView):
    permanent = True
    pattern_name = 'onboarding:manual'


def onboarding_manual(request):
    context = {'page_category': 'onboarding', 'page_name': 'manual'}

    # remove any existing onboarding process from session
    ob_process = None
    if 'onboarding_process_id' in request.session:
        ob_process = OnboardingProcess.get_by_id(request.session['onboarding_process_id'])
        if ob_process:
            device = ob_process.device.name
            onboardingProcesses.remove(ob_process)
            if ob_process.state == OnboardingProcessState.COMPLETED:
                messages.success(request, f'Device {device} onboarded successfully.')
            elif ob_process.state == OnboardingProcessState.FAILED:
                messages.error(request, f'Onboarding process for device {device} failed.')
            elif ob_process.state == OnboardingProcessState.INCORRECT_OTP:
                messages.error(
                    request, f'Client provided an incorrect credential. Onboarding for device {device} failed.'
                )
                # TODO: what to do if timeout occurs after valid LDevID is issued?
                # TODO: Should that be considered a successful onboarding?
            elif ob_process.state == OnboardingProcessState.TIMED_OUT:
                messages.error(request, f'Onboarding process for device {device} timed out.')
            else:
                messages.warning(request, f'Onboarding process for device {device} canceled.')
        del request.session['onboarding_process_id']

    # TODO: create decorator for unexpected exception handling
    if request.method == 'POST':
        if 'onboarding-start-form' in request.POST:
            onboarding_start_form = OnboardingStartForm(request.POST, request.FILES)

            if onboarding_start_form.is_valid():
                name = onboarding_start_form.cleaned_data.get('name')

                onboardingDevice = Device(
                    name=name,
                )

                p = OnboardingProcess(onboardingDevice)
                onboardingProcesses.append(p)
                request.session['onboarding_process_id'] = p.id

                # TODO: error handling
                # onboardingDevice.save()

                return redirect('onboarding:manual-client')

            # else:
            # render normal form page for now

    # else:

    context['onboarding_start_form'] = OnboardingStartForm()

    return render(request, 'onboarding/manual.html', context=context)


def onboarding_manual_client(request):
    processId = None
    ob_process = None
    if 'onboarding_process_id' in request.session:
        processId = request.session['onboarding_process_id']
        # del request.session['onboarding_process_id']
    else:
        messages.error(request, 'No onboarding process found in session.')
        return redirect('onboarding:manual')
    print(onboardingProcesses)
    ob_process = OnboardingProcess.get_by_id(processId)
    if not ob_process:
        messages.error(request, 'Onboarding process with ID {} not found.'.format(processId))
        return redirect('onboarding:manual')
    print(ob_process)
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


def trust_store(request):
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process or not ob_process.active:
        return HttpResponse('Invalid URI extension.', status=404)

    response = HttpResponse(Crypt.get_trust_store(), status=200)
    response['hmac-signature'] = ob_process.get_hmac()
    if ob_process.state == OnboardingProcessState.HMAC_GENERATED:
        ob_process.state = OnboardingProcessState.TRUST_STORE_SENT
    return response

@csrf_exempt # should be safe because we are using a OTP
def ldevid(request):
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if (not ob_process or not ob_process.active
        or ob_process.state >= OnboardingProcessState.DEVICE_VALIDATED # only ever allow one set of credentials to be submitted
        or request.method != 'POST' or not request.FILES or not request.FILES['ldevid.csr']):
        return HttpResponse('Invalid URI extension.', status=404)

    # get http basic auth header
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2:  # only basic auth is supported
            if auth[0].lower() == 'basic':
                uname, passwd = base64.b64decode(auth[1]).decode('us-ascii').split(':')
                if ob_process.check_ldevid_auth(uname, passwd):
                    csr_file = request.FILES['ldevid.csr']
                    if not csr_file or csr_file.multiple_chunks(): # stop client providing a huge file
                        return HttpResponse('Invalid CSR.', status=400)	
                    csr = csr_file.read()
                    ldevid = ob_process.sign_ldevid(csr)
                    if ldevid:
                        return HttpResponse(ldevid, status=200)
                    else:
                        return HttpResponse('Error during certificate creation.', status=500)
                    
                # ob_process canceled itself if the client provides incorrect credentials
                return HttpResponse('Invalid URI extension.', status=404)

    response = HttpResponse(status=401)
    response['WWW-Authenticate'] = 'Basic realm="%s"' % url_extension
    return response


def cert_chain(request):
    # TODO: instead of URL extension, match using the client LDevID certificate
    # TODO: chain with or without end-entity certificate?
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process or not ob_process.active:
        return HttpResponse('Invalid URI extension.', status=404)
    
    response = HttpResponse(Crypt.get_cert_chain(), status=200)
    if (ob_process.state == OnboardingProcessState.LDEVID_SENT): ob_process.state = OnboardingProcessState.COMPLETED
    return response

def state(request):
    # get URL extension
    url_extension = request.path.split('/')[-1]
    ob_process = OnboardingProcess.get_by_url_ext(url_extension)
    if not ob_process:
        return HttpResponse(str(OnboardingProcessState.NO_SUCH_PROCESS), status=404)

    response = HttpResponse(str(ob_process.state), status=200)

    return response
