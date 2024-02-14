from django.shortcuts import render, redirect
from .forms import OnboardingStartForm
from devices.models import Device
from django.http import HttpResponse
from django.views.generic.base import RedirectView
from django.contrib import messages
from .models import OnboardingProcess, onboardingProcesses

class IndexView(RedirectView):
    permanent = True
    pattern_name = 'onboarding:manual'


def onboarding_manual(request):
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual'
    }

    # remove any existing onboarding process from session
    ob_process = None
    if 'onboarding_process_id' in request.session:
        ob_process = OnboardingProcess.get_by_id(request.session['onboarding_process_id'])
        if ob_process:
            onboardingProcesses.remove(ob_process)
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
                #onboardingDevice.save()

                return redirect('onboarding:onboarding-manual-client')

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
        #del request.session['onboarding_process_id']
    else:
        messages.error(request, "No onboarding process found in session.")
        return redirect('onboarding:onboarding-manual')
    print(onboardingProcesses)
    ob_process = OnboardingProcess.get_by_id(processId)
    if not ob_process:
        messages.error(request, 'Onboarding process with ID {} not found.'.format(processId))
        return redirect('onboarding:onboarding-manual')
    print(ob_process)
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual',
        'otp' : ob_process.otp,
        'salt': ob_process.salt,
        'tpurl': '10.10.10.10',
        'url': ob_process.url,
        'device_name': ob_process.device.name
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