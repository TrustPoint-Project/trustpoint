"""Module that implements all views corresponding to the Onboarding application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from devices.models import Device
from django.contrib import messages
from django.http import Http404, HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.generic import DetailView, RedirectView, TemplateView, View

from trustpoint.views import TpLoginRequiredMixin

from .cli_builder import CliCommandBuilder
from .models import (
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
            messages.error(request, 'Onboarding: device_id kwarg not provided.')
            return False

        self.device = Device.get_by_id(device_id)
        if not self.device:
            messages.error(request, f'Onboarding: Device with ID {device_id} not found.')
            return False
        return True

    def check_onboarding_prerequisites(self, request: HttpRequest,
                                       allowed_onboarding_protocols: list[Device.OnboardingProtocol]) -> bool:
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

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Renders a template view for downloading certificate data."""
        if (not self.get_device(request)
            or not self.check_onboarding_prerequisites(request, [Device.OnboardingProtocol.MANUAL])
           ):
            return redirect(self.redirection_view)

        device = self.device

        onboarding_process = OnboardingProcess.make_onboarding_process(device, DownloadOnboardingProcess)

        messages.warning(request, 'Keep the PKCS12 file secure! It contains the private key of the device.')

        context = {
            'page_category': 'onboarding',
            'page_name': 'download',
            'url': onboarding_process.url,
            'sn': device.serial_number,
            'device_name': device.device_name,
            'device_id': device.id,
        }

        return render(request, self.template_name, context)

class P12DownloadView(TpLoginRequiredMixin, OnboardingUtilMixin, View):
    """View for downloading the PKCS12 file of a device."""

    redirection_view = 'devices:devices'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """GET method that returns the PKCS12 file of a device."""
        if not self.get_device(request) or self.device.onboarding_protocol != Device.OnboardingProtocol.MANUAL:
            return HttpResponse('Not found.', status=404)

        device = self.device
        onboarding_process = OnboardingProcess.get_by_device(device)
        if not onboarding_process or not onboarding_process.pkcs12:
            return HttpResponse('Not found.', status=404)

        return HttpResponse(onboarding_process.get_pkcs12(), content_type='application/x-pkcs12')

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
                 Device.OnboardingProtocol.MANUAL])
           ):
            return redirect(self.redirection_view)
        device = self.device

        if device.onboarding_protocol == Device.OnboardingProtocol.MANUAL:
            return ManualDownloadView.as_view()(request, *args, **kwargs)

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
            'sn': device.serial_number,
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


class Detail404RedirectionMessageView(DetailView):
    """A detail view that redirects to self.redirection_view on 404 and adds a message."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Overrides the get method to add a message and redirect to self.redirection_view on 404."""
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            if not hasattr(self, 'category'):
                self.category = 'Error'
            messages.error(self.request,
                           f'{self.category}: {self.model.__name__} with ID {kwargs[self.pk_url_kwarg]} not found.')
            return redirect(self.redirection_view)


class OnboardingExitView(TpLoginRequiredMixin, RedirectView):
    """View for canceling the onboarding process."""

    category = 'Onboarding'

    def get_redirect_url(self, **kwargs: Any) -> str: # noqa: ARG002
        """Redirects to the devices page after canceling the onboarding process."""
        return reverse('devices:devices')

    def _cancel(self, request: HttpRequest, device_id: int) -> None:
        """Cancels the onboarding process for a device."""
        device = Device.get_by_id(device_id)
        if not device:
            messages.error(request, f'Onboarding: Device with ID {device_id} not found.')
            return

        # TODO(Air): We also need to remove the onboarding process automatically without calling this view

        state, onboarding_process = OnboardingProcess.cancel_for_device(device)

        if state == OnboardingProcessState.COMPLETED:
            messages.success(request, f'Device {device.device_name} onboarded successfully.')
        elif state == OnboardingProcessState.FAILED:
            # TODO(Air): what to do if timeout occurs after valid LDevID is issued?
            # TODO(Air): Delete device and add to CRL.
            reason = onboarding_process.error_reason if onboarding_process else ''
            messages.error(request, f'Onboarding process for device {device.device_name} failed. {reason}')
        elif state == OnboardingProcessState.CANCELED:
            messages.warning(request, f'Onboarding process for device {device.device_name} canceled.')
        elif state != OnboardingProcessState.NO_SUCH_PROCESS:
            messages.error(request,
                           f'Onboarding process for device {device.device_name} is in unexpected state {state}.')

        if not onboarding_process:
            messages.error(request, f'No active onboarding process for device {device.device_name} found.')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Overrides the dispatch method to additionally call the _cancel method."""
        self._cancel(request, kwargs['device_id'])
        return super().dispatch(request, *args, **kwargs)

class OnboardingRevocationView(TpLoginRequiredMixin, Detail404RedirectionMessageView):
    """View for revoking LDevID certificates."""

    template_name = 'onboarding/revoke.html'
    model = Device
    category = 'Revocation'
    redirection_view = 'devices:devices'
    context_object_name = 'device'
    pk_url_kwarg = 'device_id'

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Revokes the LDevID certificate for a device.

        Input: device_id (int kwarg, optional): The ID of the device whose certificate to revoke.

        Redirects to the device details view.
        """
        device = self.get_object() # don't need error handling, will return 404 if missing

        if device.revoke_ldevid():
            messages.success(request, f'LDevID certificate for device {device.device_name} revoked.')
        else:
            messages.warning(request, f'Device {device.device_name} has no LDevID certificate to revoke.')
        return redirect(self.redirection_view)
