from django import forms
from django.shortcuts import render
from django.views.generic.base import RedirectView
from django.core.exceptions import ObjectDoesNotExist
from .forms import NetworkConfigForm,NTPConfigForm, LoggingConfigForm
from .models import NetworkConfig, NTPConfig, LoggingConfig
class IndexView(RedirectView):
    permanent = True
    pattern_name = 'sysconf:logging'


# Create your views here.
def logging(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'logging'
    }
    try:
        logging_config=LoggingConfig.objects.get(id=1)
    except ObjectDoesNotExist:
    # create an empty configuration
        logging_config=LoggingConfig()
        
    if request.method == 'POST':
        loggging_config_form = LoggingConfigForm(request.POST,instance=logging_config)
        if loggging_config_form.is_valid():
                
            loggging_config_form.save()
            
        context['logging_config_form'] = loggging_config_form
        return render(request, 'sysconf/logging.html', context=context)
            
    else:
        
        context['logging_config_form'] = LoggingConfigForm(instance=logging_config)
        
        return render(request, 'sysconf/logging.html', context=context)


def network(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'network'
    }
    # Try to read the configuration
    try:
        network_config=NetworkConfig.objects.get(id=1)
    except ObjectDoesNotExist:
    # create an empty configuration
        network_config=NetworkConfig()
        
    if request.method == 'POST':
        network_configuration_form = NetworkConfigForm(request.POST,instance=network_config)
        if network_configuration_form.is_valid():
                
            network_configuration_form.save()
            
        context['network_config_form'] = network_configuration_form
        return render(request, 'sysconf/network.html', context=context)
            
    else:
        
        context['network_config_form'] = NetworkConfigForm(instance=network_config)
        
        return render(request, 'sysconf/network.html', context=context)


def ntp(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'ntp'
    }
    # Try to read the configuration
    try:
        ntp_config=NTPConfig.objects.get(id=1)
    except ObjectDoesNotExist:
    # create an empty configuration
        ntp_config=NTPConfig()
        
    if request.method == 'POST':
        ntp_configuration_form = NTPConfigForm(request.POST,instance=ntp_config)
        if ntp_configuration_form.is_valid():
                
            ntp_configuration_form.save()
            
        context['ntp_config_form'] = ntp_configuration_form
        return render(request, 'sysconf/ntp.html', context=context)
            
    else:
        
        context['ntp_config_form'] = NTPConfigForm(instance=ntp_config)
        
        return render(request, 'sysconf/ntp.html', context=context)


def ssh(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'ssh'
    }
    return render(request, 'sysconf/ssh.html', context=context)
