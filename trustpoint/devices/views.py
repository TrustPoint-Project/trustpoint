from django.shortcuts import render
from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    permanent = True
    pattern_name = 'devices:devices'


def devices(request):
    context = {
        'page_category': 'devices',
        'page_name': 'devices'
    }
    return render(request, 'devices/devices.html', context=context)
