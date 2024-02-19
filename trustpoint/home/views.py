from django.shortcuts import render
from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    permanent = True
    pattern_name = 'home:dashboard'


def dashboard(request):
    context = {'page_category': 'home', 'page_name': 'dashboard'}
    return render(request, 'home/dashboard.html', context=context)
