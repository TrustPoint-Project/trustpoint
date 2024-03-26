"""Module that implements all views corresponding to the Onboarding application."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from devices.models import Device
from django.contrib import messages
from django.http import Http404, HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DetailView, RedirectView, TemplateView, View

from trustpoint.views import TpLoginRequiredMixin

from .cli_builder import CliCommandBuilder
from .crypto_backend import CryptoBackend as Crypt
from .models import (
    DownloadOnboardingProcess,
    ManualOnboardingProcess,
    OnboardingProcess,
    OnboardingProcessState,
    onboarding_processes,
)

if TYPE_CHECKING:
    from typing import Any, TypeVar

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
        device = self.device

        if not device:
            messages.error(request, f'Onboarding: Device with ID {self.kwargs['device_id']} not found.')
            return False

        if not device.endpoint_profile:
            messages.error(request,
                f'Onboarding: Please select an endpoint profile for device {device.device_name} first.')
            return False
        if not device.endpoint_profile.issuing_ca:
            messages.error(request,
                f'Onboarding: Endpoint profile {device.endpoint_profile.unique_name} has no issuing CA set.')
            return False

        if device.onboarding_protocol not in allowed_onboarding_protocols:
            try:
                label = Device.OnboardingProtocol(device.onboarding_protocol).label
            except ValueError:
                messages.error(request, 'Onboarding: Please select a valid onboarding protocol.')
                return False

            messages.error(request, f'Onboarding protocol {label} is not implemented.')
            return False

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate

        return True

    if TYPE_CHECKING:
        OnboardingProcessTypes = TypeVar('OnboardingProcessTypes', bound=OnboardingProcess)
    def make_onboarding_process(self, process_type: type[OnboardingProcessTypes]) -> OnboardingProcessTypes:
        """Returns the onboarding process for the device, creates a new one if it does not exist.

        Args:
            process_type (classname): The (class) type of the onboarding process to create.

        Returns:
            OnboardingProcessTypes: The onboarding process instance for the device.
        """
        # check if onboarding process for this device already exists
        onboarding_process = OnboardingProcess.get_by_device(self.device)

        if not onboarding_process:
            onboarding_process = process_type(self.device)
            onboarding_processes.append(onboarding_process)
            self.device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDING_RUNNING
            # TODO(Air): very unnecessary save required to update onboarding status in table
            # Problem: if server is restarted during onboarding, status is stuck at running
            self.device.save()

        return onboarding_process


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

        onboarding_process = self.make_onboarding_process(DownloadOnboardingProcess)

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

        onboarding_process = self.make_onboarding_process(ManualOnboardingProcess)

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

        if device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
            device.save()
            messages.warning(request, f'Onboarding process for device {device.device_name} canceled.')

        onboarding_process = OnboardingProcess.get_by_device(device)
        if not onboarding_process:
            messages.error(request, f'No active onboarding process for device {device.device_name} found.')
            return

        reason = onboarding_process.error_reason
        # TODO(Air): We also need to remove the onboarding process automatically without calling this view
        onboarding_processes.remove(onboarding_process)
        if onboarding_process.state == OnboardingProcessState.COMPLETED:
            messages.success(request, f'Device {device.device_name} onboarded successfully.')
        elif onboarding_process.state == OnboardingProcessState.FAILED:
            messages.error(request, f'Onboarding process for device {device.device_name} failed. {reason}')
            # TODO(Air): what to do if timeout occurs after valid LDevID is issued?
            # TODO(Air): Delete device and add to CRL.

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

        if device.ldevid:
            if device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
                # TODO(Air): Perhaps extra status for revoked devices?
                device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
            device.ldevid.delete()
            device.ldevid = None
            device.save()
            messages.success(request, f'LDevID certificate for device {device.device_name} revoked.')
        else:
            messages.warning(request, f'Device {device.device_name} has no LDevID certificate to revoke.')
        return redirect(self.redirection_view)


class GetOnboardingProcessMixin:
    """Mixin for getting the onboarding process from request URL arguments."""

    def get_onboarding_process(self: GetOnboardingProcessMixin, *,
                               accept_inactive: bool = False) -> OnboardingProcess | None:
        """Gets the onboarding process from either the URL extension or device ID.

        Args:
            accept_inactive (bool kwarg): Whether to also return an inactive onboarding process (e.g. for status).
            url_ext (str kwarg, optional): The URL extension of the onboarding process.
            device_id (int kwarg, optional): The ID of the device the onboarding process is associated with.

        Returns: The onboarding process or None if not found.
        """
        onboarding_process = None
        if 'url_ext' in self.kwargs:
            onboarding_process = OnboardingProcess.get_by_url_ext(self.kwargs['url_ext'])
        if 'device_id' in self.kwargs:
            device = Device.get_by_id(self.kwargs['device_id'])
            if device:
                onboarding_process = OnboardingProcess.get_by_device(device)
        if (not onboarding_process
            or (not onboarding_process.active and not accept_inactive)):
            exc_msg = 'Invalid URI extension.'
            raise Http404(exc_msg)
        return onboarding_process

class TrustStoreView(GetOnboardingProcessMixin, View):
    """View for the trust store API endpoint."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Returns the trust store and HMAC signature.

        Inputs: Onbarding process URL extension (in request path) as kwarg 'url_ext': str

        Returns:
            HttpResponse with the TLS Trust Store as the response body
            HMAC signature of the Trust Store as a response header.
        """
        onboarding_process = self.get_onboarding_process()
        try:
            trust_store = Crypt.get_trust_store()
        except FileNotFoundError:
            onboarding_process.fail('Trust store file not found.')
            return HttpResponse('Trust store file not found.', status=500)

        response = HttpResponse(trust_store, status=200)
        response['hmac-signature'] = onboarding_process.get_hmac()
        if onboarding_process.state == OnboardingProcessState.HMAC_GENERATED:
            onboarding_process.state = OnboardingProcessState.TRUST_STORE_SENT
        return response


@method_decorator(csrf_exempt, name='dispatch')
class LDevIDView(GetOnboardingProcessMixin, View):
    """View for the LDevID API endpoint."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Handles the LDevID certificate signing request.

        Inputs:
            Onbarding process URL extension (in request path)
            Certificate signing request (as POST file ldevid.csr)

        Returns: LDevID certificate chain (in response body)
        """
        onboarding_process = self.get_onboarding_process()
        # only ever allow one set of credentials to be submitted
        if (
            onboarding_process.state >= OnboardingProcessState.DEVICE_VALIDATED
            or request.method != 'POST'
            or not request.FILES
            or not request.FILES['ldevid.csr']
        ):
            return HttpResponse('Invalid URI extension.', status=404)

         # get http basic auth header
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2 and auth[0].lower() == 'basic':  # only basic auth is supported # noqa: PLR2004
                uname, passwd = base64.b64decode(auth[1]).decode('us-ascii').split(':')
                if onboarding_process.check_ldevid_auth(uname, passwd):
                    csr_file = request.FILES['ldevid.csr']
                    if not csr_file or csr_file.multiple_chunks():  # stop client providing a huge file
                        return HttpResponse('Invalid CSR.', status=400)
                    csr = csr_file.read()
                    ldevid =onboarding_process.sign_ldevid(csr)
                    if ldevid:
                        return HttpResponse(ldevid, status=200)

                    return HttpResponse('Error during certificate creation.', status=500)

                #onboarding_process canceled itself if the client provides incorrect credentials
                return HttpResponse('Invalid URI extension.', status=404)

        response = HttpResponse(status=401)
        response['WWW-Authenticate'] = 'Basic realm="%s"' % kwargs['url_ext']
        return response


class CertChainView(GetOnboardingProcessMixin, View):
    """View for the LDevID certificate chain API endpoint."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Returns the LDevID certificate chain.

        Inputs: Onbarding process URL extension (in request path) as kwarg 'url_ext': str

        Returns: HttpResponse with Onboarding process state as an integer (representing OnboardingProcessState enum)
        """
        onboarding_process = self.get_onboarding_process()
        chain = onboarding_process.get_cert_chain()

        # could use cryptography.x509.verification to verify the chain,
        # it has just been added in cryptography 42.0.0 and is still marked as an unstable API

        # TODO(Air): do we want to verify the LDevID as a TLS client certificate?
        # This would a) require the LDevID to have extendedKeyUsage=clientAuth and
        #            b) require Nginx/Apache to be configured to handle client certificates
        # Verifying client certificates in Django requires a custom middleware, e.g. django-ssl-auth (unmaintained!)

        if chain:
            return HttpResponse(chain, status=200)
        return HttpResponse('Invalid URI extension.', status=404)


class StateView(GetOnboardingProcessMixin, TpLoginRequiredMixin, View):
    """View for the onboarding process state API endpoint."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse: # noqa: ARG002
        """Returns the onboarding process state.

        Inputs: Onbarding process URL extension (in request path) as kwarg 'url_ext': str

        Returns: HttpResponse with Onboarding process state as an integer (representing OnboardingProcessState enum)
        """
        try:
            onboarding_process = self.get_onboarding_process(accept_inactive=True)
        except Http404:
            return HttpResponse(str(OnboardingProcessState.NO_SUCH_PROCESS), status=404)
        return HttpResponse(str(onboarding_process.state), status=200)

