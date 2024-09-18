"""Django Views"""
from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView
from django.views.generic.edit import FormView

from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    PrimaryKeyFromUrlToQuerysetMixin,
    TpLoginRequiredMixin,
)

from .forms import LoggingConfigForm, NetworkConfigForm, NTPConfigForm, SecurityConfigForm
from .models import LoggingConfig, NetworkConfig, NTPConfig, SecurityConfig
from .security.manager import SecurityFeatures, SecurityManager

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse




class SecurityLevelMixin:
    """A mixin that provides security feature checks for Django views."""

    def __init__(self, security_feature: SecurityFeatures=None, *args, **kwargs) -> None:
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

    def get_security_level(self):
        """Returns the security mode of the current security level instance.

        Returns:
        --------
        str
            The security mode of the current security level instance.
        """
        return self.sec.get_security_level()


class SecurityLevelMixinRedirect(SecurityLevelMixin):
    """A mixin that provides security feature checks for Django views with redirect feature."""

    def __init__(self, disabled_by_security_level_url=None, *args, **kwargs) -> None:
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
        self.disabled_by_security_level_url = disabled_by_security_level_url

    def dispatch(self, request, *args, **kwargs):
        """If the feature is not allowed, the user is redirected to the disabled_by_security_level_url with an error message.

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
        if not self.sec.is_feature_allowed(self.security_feature):
            msg = _('Your security setting %s does not allow the feature: %s' % (self.get_security_level(), self.security_feature.value))
            messages.error(request, msg)
            return redirect(self.disabled_by_security_level_url)
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


class LoggingConfigView(TpLoginRequiredMixin, FormView):
    template_name = 'sysconf/logging.html'
    form_class = LoggingConfigForm
    success_url = reverse_lazy('sysconf:logging')


    def get_initial(self):
        try:
            logging_config = LoggingConfig.objects.get(id=1)
            if logging_config:
                return {
                    'logging_server_address': logging_config.logging_server_address,
                    'logging_server_port': logging_config.logging_server_port,
                    'logging_type': logging_config.logging_type,
                    'network_type': logging_config.network_type}
        except ObjectDoesNotExist:
            return {}

    def form_valid(self, form):
        try:
            logging_config = LoggingConfig.objects.get(id=1)
        except ObjectDoesNotExist:
            logging_config = LoggingConfig()

        logging_config = form.save(commit=False)
        logging_config.save()

        messages.success(self.request, 'Your changes were saved successfully.')
        return super().form_valid(form)


    def form_invalid(self, form):
        messages.error(self.request, _('Error saving the configuration.'))
        return self.render_to_response(self.get_context_data(form=form))


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

