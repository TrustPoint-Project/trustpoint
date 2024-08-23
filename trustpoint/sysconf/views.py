"""Django Views"""
from __future__ import annotations

import threading
from functools import wraps
from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView

from .security.decorators import security_level
from .security.manager import SecurityFeatures, SecurityManager

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

from .forms import LoggingConfigForm, NetworkConfigForm, NTPConfigForm, SecurityConfigForm
from .models import LoggingConfig, NetworkConfig, NTPConfig, SecurityConfig


class SecurityLevelMixin:
    """A mixin that provides security featrues checks for Django views."""

    _thread_locals = threading.local()

    def __init__(self, security_feature: SecurityFeatures=None, no_permisson_url=None, *args, **kwargs) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Parameters:
        -----------
        security_feature : SecurityFeatures, optional
            The feature to check against the current security level (default is None).
        no_permisson_url : str, optional
            The URL to which the user is redirected if the feature is not allowed (default is None).
        *args, **kwargs:
            Additional arguments passed to the superclass initializer.
        """
        super().__init__(*args, **kwargs)
        self.sec = SecurityManager()
        self.security_feature = security_feature
        self.no_permisson_url = no_permisson_url

    @classmethod
    def _get_security_level_instance(cls):
        """Retrieves the current security level instance from the database, caching it in thread-local storage.

        Returns:
        --------
        SecurityConfig
            The current security level instance.
        """
        if not hasattr(cls._thread_locals, 'security_level_instance'):
            cls._thread_locals.security_level_instance = SecurityConfig.objects.first()
        return cls._thread_locals.security_level_instance

    @classmethod
    def get_security_level(cls):
        """Returns the security mode of the current security level instance.

        Returns:
        --------
        str
            The security mode of the current security level instance.
        """
        return cls._get_security_level_instance().security_mode

    @classmethod
    def refresh_security_level_instance(cls):
        """Refreshes the cached security level instance by reloading it from the database."""
        cls._thread_locals.security_level_instance = SecurityConfig.objects.first()

    def dispatch(self, request, *args, **kwargs):
        """If the feature is not allowed, the user is redirected to the no_permisson_url with an error message.

        Parameters:
        -----------
        request : HttpRequest
            The HTTP request object.
        *args, **kwargs:
            Additional arguments passed to the dispatch method.

        Returns:
        --------
        HttpResponse or HttpResponseRedirect
            The HTTP response object, either continuing to the requested view or redirecting.
        """
        if not self.sec.is_feature_allowed(self.security_feature, self.get_security_level()):
            msg = f'Your security setting does not allow the feature: "{self.security_feature}"'
            messages.error(request, _(msg))
            return redirect(self.no_permisson_url)
        return super().dispatch(request, *args, **kwargs)


class IndexView(RedirectView):
    """Index view"""
    permanent = True
    pattern_name = 'sysconf:logging'


def language(request: HttpRequest) -> HttpResponse:
    """Handle language Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'language'}
    return render(request, 'sysconf/language.html', context=context)

# Create your views here.
def logging(request: HttpRequest) -> HttpResponse:
    """Handle logging Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'logging'}
    try:
        logging_config = LoggingConfig.objects.get(id=1)
    except ObjectDoesNotExist:
        # create an empty configuration
        logging_config = LoggingConfig()

    if request.method == 'POST':
        logging_config_form = LoggingConfigForm(request.POST, instance=logging_config)
        if logging_config_form.is_valid():
            logging_config_form.save()
            messages.success(request, _('Your changes were saved successfully.'))
        else:
            messages.error(request, _('Error saving the configuration'))

        context['logging_config_form'] = logging_config_form
        return render(request, 'sysconf/logging.html', context=context)

    else:
        context['logging_config_form'] = LoggingConfigForm(instance=logging_config)

        return render(request, 'sysconf/logging.html', context=context)


def network(request: HttpRequest) -> HttpResponse:
    """Handle network Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'network'}
    # Try to read the configuration
    try:
        network_config = NetworkConfig.objects.get(id=1)
    except ObjectDoesNotExist:
        # create an empty configuration
        network_config = NetworkConfig()

    if request.method == 'POST':
        network_configuration_form = NetworkConfigForm(request.POST, instance=network_config)
        if network_configuration_form.is_valid():
            network_configuration_form.save()
            messages.success(request, _('Your changes were saved successfully.'))
        else:
            messages.error(request, _('Error saving the configuration'))

        context['network_config_form'] = network_configuration_form
        return render(request, 'sysconf/network.html', context=context)

    else:
        context['network_config_form'] = NetworkConfigForm(instance=network_config)

        return render(request, 'sysconf/network.html', context=context)


def ntp(request: HttpRequest) -> HttpResponse:
    """Handle ntp Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'ntp'}
    # Try to read the configuration
    try:
        ntp_config = NTPConfig.objects.get(id=1)
    except ObjectDoesNotExist:
        # create an empty configuration
        ntp_config = NTPConfig()

    if request.method == 'POST':
        ntp_configuration_form = NTPConfigForm(request.POST, instance=ntp_config)
        if ntp_configuration_form.is_valid():
            ntp_configuration_form.save()
            messages.success(request, _('Your changes were saved successfully.'))
        else:
            messages.error(request, _('Error saving the configuration'))
        context['ntp_config_form'] = ntp_configuration_form
        return render(request, 'sysconf/ntp.html', context=context)

    else:
        context['ntp_config_form'] = NTPConfigForm(instance=ntp_config)

        return render(request, 'sysconf/ntp.html', context=context)


def ssh(request: HttpRequest) -> HttpResponse:
    """Handle ssh Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'ssh'}
    return render(request, 'sysconf/ssh.html', context=context)

def security(request: HttpRequest) -> HttpResponse:
    """Handle ssh Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'security'}

    # Try to read the configuration
    try:
        security_config = SecurityConfig.objects.get(id=1)
    except ObjectDoesNotExist:
        # create an empty configuration
        security_config = SecurityConfig()

    if request.method == 'POST':
        security_configuration_form = SecurityConfigForm(request.POST, instance=security_config)
        if security_configuration_form.is_valid():
            security_configuration_form.save()
            messages.success(request, _('Your changes were saved successfully.'))
        else:
            messages.error(request, _('Error saving the configuration'))
        context['security_config_form'] = security_configuration_form
        return render(request, 'sysconf/security.html', context=context)

    else:
        context['security_config_form'] = SecurityConfigForm(instance=security_config)
        return render(request, 'sysconf/security.html', context=context)

