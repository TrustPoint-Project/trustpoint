from django.shortcuts import render, redirect
from .forms import OnboardingStartForm
from devices.models import Device
from django.http import HttpResponse
from .cryptoBackend import CryptoBackend as crypt
from django.views.generic.base import RedirectView
from .models import OnboardingProcess, onboardingProcesses

class IndexView(RedirectView):
    permanent = True
    pattern_name = 'onboarding:manual'


def onboarding_manual(request):
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual'
    }

    # TODO: create decorator for unexpected exception handling
    if request.method == 'POST':

        if 'onboarding-start-form' in request.POST:
            onboarding_start_form = OnboardingStartForm(request.POST, request.FILES)

            if onboarding_start_form.is_valid():
                pass
                name = onboarding_start_form.cleaned_data.get('name')

                onboardingDevice = Device(
                    name=name,
                )

                p = OnboardingProcess(onboardingDevice)
                onboardingProcesses.append(p)
                request.session['onboarding_process_id'] = p.id

                # TODO: error handling
                #onboardingDevice.save()

                return redirect('onboarding:onboarding-manual-client')

            # else:
                # render normal form page for now

    # else:

    context['onboarding_start_form'] = OnboardingStartForm()

    return render(request, 'onboarding/manual.html', context=context)

def onboarding_manual_client(request):
    processId = None
    #ob_process = None
    if 'onboarding_process_id' in request.session:
        processId = request.session['onboarding_process_id']
        #del request.session['onboarding_process_id']
    else:
        return HttpResponse('No onboarding process found in session.', status=400)
    for process in onboardingProcesses:
        if process.id == processId:
            ob_process = process
            break
        else:
            return HttpResponse('Onboarding process with ID {} not found.'.format(processId), status=404)
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual',
        'otp' : crypt.random_hex_string(8),
        'salt': crypt.random_hex_string(8),
        'tpurl': '10.10.10.10',
        'url': ob_process.url
    }
    return render(request, 'onboarding/manual/client.html', context=context)

def trust_store(request):
    context = {
        'page_category': 'onboarding',
        'page_name': 'trust-store'
    }
    # get URL extension
    uri_extension = request.path.split('/')[-1]
    if (uri_extension == 'abcdef'):
        return HttpResponse('It\'s a truststore baby.', status=200)
    return HttpResponse('Invalid URI extension.', status=404)