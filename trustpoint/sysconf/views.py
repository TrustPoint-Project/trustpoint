"""Django Views"""
from __future__ import annotations

from time import sleep
from typing import TYPE_CHECKING

import subprocess
import logging
from datetime import datetime
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView
from django.views.generic.edit import FormView, View
from pathlib import Path
from django.conf import settings

from trustpoint.views.base import (
    TpLoginRequiredMixin,
)

from .forms import LoggingConfigForm, NetworkConfigForm, NTPConfigForm, SecurityConfigForm
from .models import LoggingConfig, NetworkConfig, NTPConfig, SecurityConfig
from .security.manager import SecurityFeatures, SecurityManager
from .utils import NTPStatusChecker, NTPRestart, NTPConnectionTester

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

logger = logging.getLogger('tp.sysconf')

STATE_FILE_DIR = Path('/etc/trustpoint/ntp/')
SCRIPT_NTP_STATUS = STATE_FILE_DIR / Path('ntp_status.sh')
SCRIPT_START_NTP = STATE_FILE_DIR / Path('start_ntp.sh')
SCRIPT_STOP_NTP = STATE_FILE_DIR / Path('stop_ntp.sh')
SCRIPT_UPDATE_NTP_CONFIG = STATE_FILE_DIR / Path('update_ntp_config.sh')
SCRIPT_RESTART_NTP = STATE_FILE_DIR / Path('restart_ntp.sh')

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
    extra_context = {'page_category': 'sysconf', 'page_name': 'logging'}

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


@login_required
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

    context['network_config_form'] = NetworkConfigForm(instance=network_config)
    return render(request, 'sysconf/network.html', context=context)

class ManageNTPConfigView(View):
    """Class-based view to display, update, and manage NTP configuration."""
    template_name = "sysconf/ntp.html"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.docker_container = settings.DOCKER_CONTAINER

    def get(self, request):
        """Render the NTP configuration form."""
        form, ntp_config_stored, ntp_enabled, ntp_available = self._initialize_ntp_config()

        if self.docker_container:
            status_checker = NTPStatusChecker(SCRIPT_NTP_STATUS)
            ntp_enabled, message_level, message_text = status_checker.check_status()
            messages.add_message(request, message_level, message_text)

        return render(request, self.template_name, {
            "form": form,
            "ntp_enabled": ntp_enabled,
            "ntp_available": ntp_available,
            "ntp_config_stored": ntp_config_stored,
        })

    def post(self, request):
        """Handle form submission and update NTP configuration."""
        if not self.docker_container:
            return self._render_disabled_config()

        config, ntp_config_stored = self._fetch_or_create_config()
        form = NTPConfigForm(request.POST, instance=config)

        if not form.is_valid():
            return self._handle_invalid_form(request, form)

        config = form.save()
        try:
            self._apply_ntp_configuration(request, config)
            self._test_ntp_connection(request, config)
            ntp_enabled = self._restart_ntp_service(request)
        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")

        return self._render_response(request, config, ntp_enabled)

    def _initialize_ntp_config(self):
        config = NTPConfig.objects.first() or NTPConfig()
        form = NTPConfigForm(instance=config)
        ntp_config_stored = bool(NTPConfig.objects.exists())
        ntp_enabled, ntp_available = False, self.docker_container
        return form, ntp_config_stored, ntp_enabled, ntp_available

    def _fetch_or_create_config(self):
        try:
            config = NTPConfig.objects.first() or NTPConfig()
            ntp_config_stored = bool(NTPConfig.objects.exists())
            return config, ntp_config_stored
        except Exception as e:
            raise Exception(f"Failed to fetch or create NTPConfig instance: {str(e)}")

    def _handle_invalid_form(self, request, form):
        messages.error(request, "Invalid form data.")
        ntp_enabled = self._get_ntp_status(request)
        return render(request, self.template_name, {
            "form": form,
            "ntp_enabled": ntp_enabled,
            "ntp_available": True,
            "ntp_config_stored": bool(NTPConfig.objects.exists()),
        })

    def _apply_ntp_configuration(self, request, config):
        if not SCRIPT_UPDATE_NTP_CONFIG.exists():
            raise FileNotFoundError(f"Script not found: {SCRIPT_UPDATE_NTP_CONFIG}")

        result = subprocess.run(
            ['sudo', str(SCRIPT_UPDATE_NTP_CONFIG), config.ntp_server_address, str(config.server_port)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            messages.success(request, "Configuration saved and applied successfully.")
        else:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

    def _test_ntp_connection(self, request, config):
        try:
            ntp_tester = NTPConnectionTester()
            success, result = ntp_tester.test_connection(config.ntp_server_address, config.server_port)
            if success:
                messages.success(request, result)
            else:
                raise Exception(result)
        except Exception as e:
            messages.error(request, str(e))
            raise

    def _restart_ntp_service(self, request):
        ntp_restarter = NTPRestart(SCRIPT_RESTART_NTP)

        status_checker = NTPStatusChecker(SCRIPT_NTP_STATUS)
        ntp_enabled, message_level, message_text = status_checker.check_status()

        if not ntp_enabled:
            return ntp_enabled

        restart_successful, restart_message = ntp_restarter.restart()
        sleep(5)

        ntp_enabled, message_level, message_text = status_checker.check_status()
        if restart_successful:
            if ntp_enabled:
                messages.success(request, restart_message)
            else:
                messages.warning(request, "Restart was successful but NTP is disabled.")
        else:
            messages.warning(request, restart_message)

        messages.add_message(request, message_level, message_text)

        return ntp_enabled

    def _get_ntp_status(self, request):
        status_checker = NTPStatusChecker(SCRIPT_NTP_STATUS)
        ntp_enabled, message_level, message_text = status_checker.check_status()
        messages.add_message(request, message_level, message_text)
        return ntp_enabled

    def _render_disabled_config(self):
        return render(self.template_name, {
            "form": NTPConfigForm(),
            "ntp_enabled": False,
            "ntp_available": False,
            "ntp_config_stored": False,
        })

    def _render_response(self, request, config, ntp_enabled):
        return render(request, self.template_name, {
            "form": NTPConfigForm(instance=config),
            "ntp_enabled": ntp_enabled,
            "ntp_available": True,
            "ntp_config_stored": bool(NTPConfig.objects.exists()),
        })


class ToggleNTPView(View):
    """
    Class-based view to enable or disable NTP synchronization.
    """

    def post(self, request, enable):
        """
        Enable or disable NTP based on the `enable` parameter.
        :param enable: A string indicating "true" or "false".
        """
        enable = enable.lower() == "true"

        try:
            config = NTPConfig.objects.first()
            if not config:
                messages.error(request, "No NTP configuration found.")
                return redirect("sysconf:ntp")

            if enable:
                self._enable_ntp(request, config)
            else:
                self._disable_ntp(request, config)

            config.save()
            sleep(5)

        except FileNotFoundError as e:
            messages.error(request, f"Script error: {e}")
        except subprocess.CalledProcessError as e:
            error_message = (
                f"Failed to toggle NTP. Command: {e.cmd}, Return Code: {e.returncode}, "
                f"Output: {e.output}, Error: {e.stderr}"
            )
            messages.error(request, error_message)
        except Exception as e:
            messages.error(request, f"Unexpected error: {str(e)}")

        return redirect("sysconf:ntp")

    def _enable_ntp(self, request, config):
        """
        Enable NTP synchronization.
        """
        if not SCRIPT_START_NTP.exists():
            raise FileNotFoundError(f"Script not found: {SCRIPT_START_NTP}")

        result = subprocess.run(
            ['sudo', str(SCRIPT_START_NTP)],
            capture_output=True,
            text=True
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args, output=stdout, stderr=stderr)

        config.enabled = True
        messages.success(request, "NTP enabled.")

    def _disable_ntp(self, request, config):
        """
        Disable NTP synchronization.
        """
        if not SCRIPT_STOP_NTP.exists():
            raise FileNotFoundError(f"Script not found: {SCRIPT_STOP_NTP}")

        result = subprocess.run(
            ['sudo', str(SCRIPT_STOP_NTP)],
            capture_output=True,
            text=True
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args, output=stdout, stderr=stderr)

        config.enabled = False
        messages.success(request, "NTP disabled successfully.")

class NTPStatusView(View):
    """Class-based view to check the current NTP status."""

    def post(self, request):
        """Handles the Check Status button action."""
        try:
            if not SCRIPT_NTP_STATUS.exists():
                raise FileNotFoundError(f"Script not found: {SCRIPT_NTP_STATUS}")

            result = subprocess.run(
                ['sudo', str(SCRIPT_NTP_STATUS)],
                capture_output=True,
                text=True
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode == 0:
                messages.success(request, f"NTP Status: {stdout}")
            else:
                messages.error(request, f"Failed to fetch NTP status: {stderr}")
        except FileNotFoundError as e:
            messages.error(request, f"Script error: {e}")
        except subprocess.CalledProcessError as e:
            error_message = f"Failed to fetch NTP status: {e.stderr if e.stderr else 'Unknown error'}"
            messages.error(request, error_message)
        except Exception as e:
            messages.error(request, f"Unexpected error: {str(e)}")

        return redirect("sysconf:ntp")


@login_required
def ssh(request: HttpRequest) -> HttpResponse:
    """Handle ssh Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'sysconf', 'page_name': 'ssh'}
    return render(request, 'sysconf/ssh.html', context=context)


@login_required
def security(request: HttpRequest) -> HttpResponse:
    """Handle Security Configuration

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
            # use a new form instance to apply new original values
            context['security_config_form'] = SecurityConfigForm(instance=security_config)
            return render(request, 'sysconf/security.html', context=context)

        messages.error(request, _('Error saving the configuration'))
        context['security_config_form'] = security_configuration_form
        return render(request, 'sysconf/security.html', context=context)

    context['security_config_form'] = SecurityConfigForm(instance=security_config)
    return render(request, 'sysconf/security.html', context=context)
