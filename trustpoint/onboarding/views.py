from django.shortcuts import render, redirect
from .forms import OnboardingStartForm
from devices.models import Device
from django.http import HttpResponse
from .cryptoBackend import CryptoBackend as crypt
from django.views.generic.base import RedirectView


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

                # TODO: error handling
                onboardingDevice.save()
                return redirect('onboarding:onboarding-manual-client')

            # else:
                context['onboarding_start_form'] = OnboardingStartForm()
                return render(request, 'pki/issuing_ca/add/local_file.html', context=context)

    # else:

    context['onboarding_start_form'] = OnboardingStartForm()

    return render(request, 'onboarding/manual.html', context=context)

def onboarding_manual_client(request):
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual',
        'otp' : crypt.random_hex_string(8),
        'salt': crypt.random_hex_string(8),
        'tpurl': '10.10.10.10',
        'url': crypt.random_character_string(6)
    }
    return render(request, 'onboarding/manual/client.html', context=context)