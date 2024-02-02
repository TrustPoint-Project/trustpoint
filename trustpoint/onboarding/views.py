from django.shortcuts import render, redirect


def onboarding(request):
    return redirect(request, 'onboarding-manual')


def onboarding_manual(request):
    context = {
        'page_category': 'onboarding',
        'page_name': 'manual'
    }
    return render(request, 'onboarding/manual.html', context=context)
