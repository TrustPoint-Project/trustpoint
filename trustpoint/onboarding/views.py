"""Module that implements all views corresponding to the Onboarding application."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from devices.models import Device
from django.contrib import messages
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic import DetailView, FormView, RedirectView, TemplateView, View

from trustpoint.views.base import TpLoginRequiredMixin

from .cli_builder import CliCommandBuilder
from .forms import BrowserLoginForm, RevokeCertificateForm
from .models import (
    BrowserOnboardingProcess,
    DownloadOnboardingProcess,
    ManualOnboardingProcess,
    OnboardingProcess,
    OnboardingProcessState,
)

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest


class OnboardingUtilMixin:
    """Mixin for checking onboarding prerequisits."""

    def get_device(self, request: HttpRequest) -> bool:
        """Adds the device attribute to self, adds an error message if it does not exist."""
        try:
            device_id = self.kwargs['device_id']
        except KeyError:
            messages.error(request, _('Onboarding: device_id kwarg not provided.'))
            return False

        self.device = Device.get_by_id(device_id)
        if not self.device:
            messages.error(request, _('Onboarding: Device with ID %s not found.') % device_id)
            return False
        return True

    def check_onboarding_prerequisites(
        self, request: HttpRequest, allowed_onboarding_protocols: list[Device.OnboardingProtocol]
    ) -> bool:
        """Checks if criteria for starting the onboarding process are met."""
        ok, msg = Device.check_onboarding_prerequisites(self.kwargs['device_id'], allowed_onboarding_protocols)

        if not ok:
            messages.error(request, msg)
            return False

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate

        return True


class ManualDownloadView(TpLoginRequiredMixin, OnboardingUtilMixin, TemplateView):
    """View for downloading the certificate, and if applicable, the private key of a device."""

    template_name = 'onboarding/manual/download.html'
    redirection_view = 'devices:devices'
    context_object_name = 'device'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:  # noqa: ARG002
        """Renders a template view for downloading certificate data."""
        if not self.get_device(request) or not self.check_onboarding_prerequisites(
            request, [Device.OnboardingProtocol.MANUAL]
        ):
            return redirect(self.redirection_view)

        device = self.device

        onboarding_process = OnboardingProcess.make_onboarding_process(device, DownloadOnboardingProcess)

        messages.warning(request, _('Keep the PKCS12 file secure! It contains the private key of the device.'))

        context = {
            'page_category': 'onboarding',
            'page_name': 'download',
            'url': onboarding_process.url,
            'sn': device.device_serial_number,
            'device_name': device.device_name,
            'device_id': device.id,
            'download_token': onboarding_process.download_token,
        }

        return render(request, self.template_name, context)


class BrowserInitializationView(TpLoginRequiredMixin, OnboardingUtilMixin, TemplateView, FormView):
    """View for initializing browser-based onboarding and downloading certificates."""

    template_name = 'onboarding/manual/browser.html'
    redirection_view = 'devices:devices'
    context_object_name = 'device'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:  # noqa: ARG002
        """Renders a template view for downloading certificate data."""
        if not self.get_device(request) or not self.check_onboarding_prerequisites(
            request, [Device.OnboardingProtocol.BROWSER]
        ):
            return redirect(self.redirection_view)

        device = self.device

        onboarding_process = OnboardingProcess.make_onboarding_process(device, BrowserOnboardingProcess)

        otp = secrets.token_hex(8)
        onboarding_process.set_otp(otp)

        context = {
            'page_category': 'onboarding',
            'page_name': 'browser',
            'url': request.path,
            'sn': device.device_serial_number,
            'device_name': device.device_name,
            'device_id': device.id,
            'otp': otp,
            'download_url': request.build_absolute_uri(reverse('onboarding:browser-login')),
        }

        return render(request, self.template_name, context)


class BrowserDownloadView(OnboardingUtilMixin, TemplateView):
    """View for handling browser download requests."""

    template_name = 'onboarding/manual/browser-download.html'
    redirection_view = 'devices:devices'

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles POST request for downloading certificates in the browser."""
        if not self.get_device(request) or not self.check_onboarding_prerequisites(
            request, [Device.OnboardingProtocol.BROWSER]
        ):
            return redirect(self.redirection_view)

        device = self.device
        onboarding_process = OnboardingProcess.get_by_device(device)
        onboarding_process.start_onboarding()

        context = {
            'page_category': 'onboarding',
            'page_name': 'browser',
            'url': onboarding_process.url,
            'device_name': device.device_name,
            'device_id': device.id,
            'download_token': onboarding_process.download_token,
        }
        return render(request, self.template_name, context)


class BrowserLoginView(OnboardingUtilMixin, FormView):
    """View to handle certificate download requests."""

    template_name = 'onboarding/manual/browser-login.html'
    form_class = BrowserLoginForm

    def post(self, request, *args, **kwargs):
        """Handles POST request for browser login form submission."""
        form = BrowserLoginForm(request.POST)
        if not form.is_valid():
            messages.error(request, _('Device or password does not match.'))
            return redirect(request.path)

        device_id = form.cleaned_data['device_id']
        otp = form.cleaned_data['otp']
        self.device = Device.get_by_id(device_id)
        onboarding_process = OnboardingProcess.get_by_device(self.device)

        if onboarding_process:
            result, tries_left = onboarding_process.check_otp(otp)
            if result:
                return BrowserDownloadView.as_view()(request, device_id=device_id, *args, **kwargs)
            if tries_left == 1:
                msg = ('Device or password does not match. \n %s try left.' % tries_left)
            elif tries_left == 0:
                msg = ('There are no tries left. Onboarding aborted')
            else:
                msg = ('Device or password does not match. \n %s tries left.' % tries_left)
        else:
            msg = ('No Onboarding for device %s found.' % device_id)

        messages.error(request, _(msg))
        return redirect(request.path)


class P12DownloadView(OnboardingUtilMixin, View):
    """View for downloading the PKCS12 file of a device."""

    redirection_view = 'devices:devices'
    success_url = reverse_lazy('devices:devices')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:  # noqa: ARG002
        """GET method that returns the PKCS12 file of a device."""
        if not self.get_device(request) and (self.device.onboarding_protocol in (Device.OnboardingProtocol.MANUAL, Device.OnboardingProtocol.BROWSER)):
            return HttpResponse('Not found.', status=404)

        device = self.device
        download_token = request.GET.get('token')
        onboarding_process = OnboardingProcess.get_by_device(device)
        if not onboarding_process or not onboarding_process.cred_serializer or not download_token:
            return HttpResponse('Not found.', status=404)

        if download_token == onboarding_process.download_token:
            response = HttpResponse(onboarding_process.get_pkcs12(),content_type='application/x-pkcs12')
            response['Content-Disposition'] = f'attachment; filename="{device.device_name}.p12"'
            return response
        return HttpResponse('Not found.', status=404)


class PemDownloadView(OnboardingUtilMixin, View):
    """View for downloading the PEM file of a device."""

    redirection_view = 'devices:devices'
    success_url = reverse_lazy('devices:devices')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """GET method that returns the PEM file of a device."""
        if not self.get_device(request) and (self.device.onboarding_protocol in (Device.OnboardingProtocol.MANUAL, Device.OnboardingProtocol.BROWSER)):
            return HttpResponse('Not found.', status=404)

        device = self.device
        download_token = request.GET.get('token')
        onboarding_process = OnboardingProcess.get_by_device(device)
        if not onboarding_process or not onboarding_process.cred_serializer or not download_token:
            return HttpResponse('Not found.', status=404)

        if download_token == onboarding_process.download_token:
            response = HttpResponse(onboarding_process.get_pem_zip(), content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{device.device_name}.zip"'
            return response
        return HttpResponse('Not found.', status=404)

# JAVA KEY STORE NOT IMPLEMENTED YET
class JavaKeyStoreDownloadView(TpLoginRequiredMixin, OnboardingUtilMixin, View):
    """View for downloading the Java KeyStore file of a device."""

    redirection_view = 'devices:devices'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """GET method that returns the Java KeyStore file of a device."""
        if not self.get_device(request) and (self.device.onboarding_protocol != Device.OnboardingProtocol.MANUAL or self.device.onboarding_protocol != Device.OnboardingProtocol.BROWSER):
            return HttpResponse('Not found.', status=404)

        device = self.device
        onboarding_process = OnboardingProcess.get_by_device(device)
        if not onboarding_process or not onboarding_process.keystore:
            return HttpResponse('Not found.', status=404)

        keystore_data = onboarding_process.get_keystore()
        response = HttpResponse(keystore_data, content_type='application/x-java-keystore')
        response['Content-Disposition'] = f'attachment; filename="{device.device_name}.jks"'
        return response


class ManualOnboardingView(TpLoginRequiredMixin, OnboardingUtilMixin, View):
    """View for the manual onboarding with Trustpoint client (cli command and status display) page."""

    redirection_view = 'devices:devices'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """GET method that selects the appropriate view based on the onboarding protocol.

        Args: device_id (int kwarg): The ID of the device to onboard.

        Returns: The rendered view for the onboarding process.
        """
        if (not self.get_device(request) or not self.check_onboarding_prerequisites(request,
                [Device.OnboardingProtocol.CLI,
                 Device.OnboardingProtocol.TP_CLIENT,
                 Device.OnboardingProtocol.MANUAL,
                 Device.OnboardingProtocol.BROWSER])
           ):
            return redirect(self.redirection_view)
        device = self.device

        if device.onboarding_protocol == Device.OnboardingProtocol.MANUAL:
            return ManualDownloadView.as_view()(request, *args, **kwargs)

        if device.onboarding_protocol == Device.OnboardingProtocol.BROWSER:
            return BrowserInitializationView.as_view()(request, *args, **kwargs)

        onboarding_process = OnboardingProcess.make_onboarding_process(device, ManualOnboardingProcess)

        context = {
            'page_category': 'onboarding',
            'page_name': 'manual',
            'otp': onboarding_process.otp,
            'salt': onboarding_process.salt,
            'tsotp': onboarding_process.tsotp,
            'tssalt': onboarding_process.tssalt,
            'host': request.get_host(),
            'url': onboarding_process.url,
            'sn': device.device_serial_number,
            'device_name': device.device_name,
            'device_id': device.id,
        }

        if device.onboarding_protocol == Device.OnboardingProtocol.TP_CLIENT:
            context['cmd_0'] = CliCommandBuilder.trustpoint_client_provision(context)
            return render(request, 'onboarding/manual/client.html', context=context)

        if device.onboarding_protocol == Device.OnboardingProtocol.CLI:
            context['cmd_1'] = [CliCommandBuilder.cli_mkdir_trustpoint()]
            context['cmd_1'].append(CliCommandBuilder.cli_get_trust_store(context))
            context['cmd_1'].append(CliCommandBuilder.cli_get_header_hmac())
            context['cmd_1'].append(CliCommandBuilder.cli_get_kdf(context))
            context['cmd_1'].append(CliCommandBuilder.cli_calc_hmac())
            context['cmd_1'].append(CliCommandBuilder.cli_compare_hmac())

            context['cmd_2'] = [CliCommandBuilder.cli_gen_key_and_csr()]
            context['cmd_2'].append(CliCommandBuilder.cli_get_ldevid(context))
            context['cmd_2'].append(CliCommandBuilder.cli_rm_csr())

            context['cmd_3'] = [CliCommandBuilder.cli_get_cert_chain(context)]

        return render(request, 'onboarding/manual/cli.html', context=context)

    def post(self, request, *args, **kwargs):
        self.get_device(request)
        if self.device.onboarding_protocol == Device.OnboardingProtocol.BROWSER:
            return BrowserInitializationView.as_view()(request, *args, **kwargs)
        return None


class Detail404RedirectionMessageView(DetailView):
    """A detail view that redirects to self.redirection_view on 404 and adds a message."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Overrides the get method to add a message and redirect to self.redirection_view on 404."""
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            if not hasattr(self, 'category'):
                self.category = _('Error')
            messages.error(
                self.request, f'{self.category}: {self.model.__name__} with ID {kwargs[self.pk_url_kwarg]} not found.'
            )
            return redirect(self.redirection_view)


class OnboardingExitView(TpLoginRequiredMixin, RedirectView):
    """View for canceling the onboarding process."""

    category = 'Onboarding'

    def get_redirect_url(self, **kwargs: Any) -> str:  # noqa: ARG002
        """Redirects to the devices page after canceling the onboarding process."""
        return reverse('devices:devices')

    def _cancel(self, request: HttpRequest, device_id: int) -> None:
        """Cancels the onboarding process for a device."""
        device = Device.get_by_id(device_id)
        if not device:
            messages.error(request, _('Onboarding: Device with ID %s not found.') % device_id)
            return

        state, onboarding_process = OnboardingProcess.cancel_for_device(device)

        if state == OnboardingProcessState.COMPLETED:
            messages.success(request, _('Onboarding: Device %s onboarded successfully.') % device.device_name)
        elif state == OnboardingProcessState.FAILED:
            reason = onboarding_process.error_reason if onboarding_process else ''
            messages.error(
                request,
                _('Onboarding process for device %(name)s failed. %(reason)s')
                % {'name': device.device_name, 'reason': reason},
            )
        elif state == OnboardingProcessState.CANCELED:
            messages.warning(request, _('Onboarding process for device %s canceled.') % device.device_name)
        elif state != OnboardingProcessState.NO_SUCH_PROCESS:
            messages.error(
                request,
                _('Onboarding process for device %(name)s is in unexpected state %(state)s.')
                % {'name': device.device_name, 'state': state},
            )

        if not onboarding_process:
            messages.error(request, _('No active onboarding process for device %s found.') % device.device_name)

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Overrides the dispatch method to additionally call the _cancel method."""
        self._cancel(request, kwargs['device_id'])
        return super().dispatch(request, *args, **kwargs)


class OnboardingRevocationView(TpLoginRequiredMixin, Detail404RedirectionMessageView):
    """View for revoking LDevID certificates."""

    template_name = 'onboarding/revoke.html'
    model = Device
    category = _('Revocation')
    redirection_view = 'devices:devices'
    context_object_name = 'device'
    pk_url_kwarg = 'device_id'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        device = self.get_object()
        context['onboarded'] = device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED
        context['form'] = RevokeCertificateForm()
        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Revokes the LDevID certificate for a device.

        Input: device_id (int kwarg, optional): The ID of the device whose certificate to revoke.

        Redirects to the device details view.
        """
        device = self.get_object()  # don't need error handling, will return 404 if missing

        form = RevokeCertificateForm(request.POST)
        if form.is_valid():
            revocation_reason = form.cleaned_data['revocation_reason']
            if device.revoke_ldevid(revocation_reason):
                messages.success(request, _('LDevID certificate for device %s revoked.') % device.device_name)
            else:
                messages.warning(request, _('Device %s has no LDevID certificate to revoke.') % device.device_name)
            return redirect(self.redirection_view)
        return redirect(self.redirection_view)
