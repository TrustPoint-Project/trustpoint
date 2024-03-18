"""Module that implements all views corresponding to the Onboarding application."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from django.http.request import HttpRequest as HttpRequest

from devices.models import Device
from django.contrib import messages
from django.http import HttpResponse, Http404
from django.shortcuts import redirect, render
from django.views.generic import View, TemplateView, DetailView, RedirectView
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from trustpoint.views import TpLoginRequiredMixin
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.utils.decorators import method_decorator

from .cli_builder import CliCommandBuilder
from .crypto_backend import CryptoBackend as Crypt
from .models import OnboardingProcess, OnboardingProcessState, onboarding_processes

if TYPE_CHECKING:
    from django.http import HttpRequest


class ManualOnboardingView(TpLoginRequiredMixin, DetailView):
    """View for the manual onboarding with Trustpoint client (cli command and status display) page."""

    template_name = 'onboarding/manual/client.html'
    model = Device
    category = 'Onboarding'
    redirection_view = 'devices:devices'
    context_object_name = 'device'
    pk_url_kwarg = 'device_id'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """View for the manual onboarding with Trustpoint client (cli command and status display) page."""
        device = self.get_object()

        if not device:
            messages.error(request, f'Onboarding: Device with ID {kwargs["device_id"]} not found.')
            return redirect(self.redirection_view)

        # choose the onboarding method for this device
        if device.onboarding_protocol not in {Device.OnboardingProtocol.CLIENT, Device.OnboardingProtocol.MANUAL}:
            try:
                label = Device.OnboardingProtocol(device.onboarding_protocol).label
            except ValueError:
                messages.error(request, 'Onboarding: Please select a valid onboarding protocol.')
                return redirect(self.redirection_view)

            messages.error(request, f'Onboarding protocol {label} is not implemented.')
            return redirect(self.redirection_view)

        # check that endpoint profile is set
        if not device.endpoint_profile:
            messages.error(
                request,
                f'Onboarding: Please select an endpoint profile for device {device.device_name} first.')
            return redirect(self.redirection_view)

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate

        # check if onboarding process for this device already exists
        onboarding_process = OnboardingProcess.get_by_device(device)

        if not onboarding_process:
            onboarding_process = OnboardingProcess(device)
            onboarding_processes.append(onboarding_process)
            device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDING_RUNNING
            # TODO(Air): very unnecessary save required to update onboarding status in table
            # Problem: if server is restarted during onboarding, status is stuck at running
            device.save()

        context = {
            'page_category': 'onboarding',
            'page_name': 'manual',
            'otp':onboarding_process.otp,
            'salt':onboarding_process.salt,
            'tsotp':onboarding_process.tsotp,
            'tssalt':onboarding_process.tssalt,
            'host': request.get_host(),
            'url':onboarding_process.url,
            'sn':device.serial_number,
            'device_name':device.device_name,
            'device_id':device.id,
        }

        if device.onboarding_protocol == Device.OnboardingProtocol.CLIENT:
            context['cmd_0'] = CliCommandBuilder.trustpoint_client_provision(context)
            return render(request, 'onboarding/manual/client.html', context=context)

        if device.onboarding_protocol == Device.OnboardingProtocol.MANUAL:
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
    """A detail view that redirects to the devices page on 404 and adds a message."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if not hasattr(self, 'category'): self.category = 'Error'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any):
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            messages.error(self.request,
                           f'{self.category}: {self.model.__name__} with ID {kwargs[self.pk_url_kwarg]} not found.')
            return redirect(self.redirection_view)
        

class OnboardingExitView(TpLoginRequiredMixin, RedirectView):
    """View for canceling the onboarding process."""

    category = 'Onboarding'

    def get_redirect_url(self, **kwargs: Any):
        return reverse('devices:devices')
    
    def _cancel(self, request: HttpRequest, device_id: int):
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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any):
        """Revokes the LDevID certificate for a device."""
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
    """Mixin for getting the onboarding process from the URL extension."""

    def get_onboarding_process(self: GetOnboardingProcessMixin, *,
                               accept_inactive: bool = False) -> OnboardingProcess | None:
        """Gets the onboarding process from the URL extension."""
        onboarding_process = OnboardingProcess.get_by_url_ext(self.kwargs['url_ext'])
        if (not onboarding_process
            or (not onboarding_process.active and not accept_inactive)):
            raise Http404('Invalid URI extension.')
        return onboarding_process
    
class TrustStoreView(GetOnboardingProcessMixin, View):
    """View for the trust store API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns:
        Trust store (in response body)
        HMAC signature of trust store (in response header)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Returns the trust store and HMAC signature."""
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
    """View for the LDevID API endpoint.

    Request type: POST

    Inputs:
        Onbarding process URL extension (in request path)
        Certificate signing request (as POST file ldevid.csr)

    Returns: LDevID certificate chain (in response body)
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles the LDevID certificate signing request."""
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
        response['WWW-Authenticate'] = 'Basic realm="%s"' % kwargs["url_ext"]
        return response
    

class CertChainView(GetOnboardingProcessMixin, View):
    """View for the LDevID certificate chain API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns: LDevID certificate chain (in response body)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Returns the LDevID certificate chain."""
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
    """View for the onboarding process state API endpoint.

    Request type: GET

    Inputs: Onbarding process URL extension (in request path)

    Returns: Onboarding process state as an integer (representing OnboardingProcessState enum, in response body)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Returns the onboarding process state."""
        try:
            onboarding_process = self.get_onboarding_process(accept_inactive=True)
        except Http404:
            return HttpResponse(str(OnboardingProcessState.NO_SUCH_PROCESS), status=404)
        return HttpResponse(str(onboarding_process.state), status=200)

