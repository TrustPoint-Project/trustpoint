"""This module contains all views concerning the devices application."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, cast

from core.file_builder.enum import ArchiveFormat
from core.serializer import CredentialSerializer
from core.validator.field import UniqueNameValidator
from django.contrib import messages  # type: ignore[import-untyped]
from django.http import FileResponse, Http404, HttpResponse  # type: ignore[import-untyped]
from django.shortcuts import redirect, render  # type: ignore[import-untyped]
from django.urls import reverse, reverse_lazy  # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from django.views.generic.base import RedirectView  # type: ignore[import-untyped]
from django.views.generic.detail import DetailView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView, FormView  # type: ignore[import-untyped]
from django_tables2 import SingleTableView  # type: ignore[import-untyped]  # type: ignore[import-untyped]
from django.contrib import messages
from django.forms import BaseModelForm
from django.http import FileResponse, Http404, HttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormView

# TODO(AlexHx8472): Remove django_tables2 dependency, and thus remove the type: ignore[misc]
from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from pki.models.credential import CredentialModel

from devices.forms import (
    BrowserLoginForm,
    CredentialDownloadForm,
    IssueDomainCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
)
from devices.models import (
    DeviceModel,
    IssuedApplicationCertificateModel,
    IssuedDomainCredentialModel,
    RemoteDeviceCredentialDownloadModel,
)
from devices.tables import DeviceApplicationCertificatesTable, DeviceDomainCredentialsTable, DeviceTable
from trustpoint.views.base import TpLoginRequiredMixin

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from typing import ClassVar

    from django.forms import BaseModelForm
    import ipaddress
    from typing import Any, ClassVar

    from django.http.request import HttpRequest


class DevicesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the devices application."""

    permanent = False
    pattern_name = 'devices:devices'


class DeviceContextMixin:
    """Mixin which adds context_data for the Devices -> Devices pages."""

    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'devices'}


class DownloadTokenRequiredMixin:
    """Mixin which checks the token included in the URL for browser download views."""

    def dispatch(self, request, *args: tuple, **kwargs: dict) -> HttpResponse:
        token = request.GET.get('token')
        try:
            self.credential_download = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=kwargs.get('pk'))
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            messages.warning(request, 'Invalid download token.')
            return redirect('devices:browser_login')
        if not token or not self.credential_download.check_token(token):
            messages.warning(request, 'Invalid download token.')
            return redirect('devices:browser_login')
        return super().dispatch(request, *args, **kwargs)


# TODO(AlexHx8472): Remove django_tables2 dependency, and thus remove the type: ignore[misc]
class DeviceTableView(DeviceContextMixin, TpLoginRequiredMixin, SingleTableView):  # type: ignore[misc]
    """Endpoint Profiles List View."""

    http_method_names = ('get',)

    model = DeviceModel
    table_class = DeviceTable
    template_name = 'devices/devices.html'
    context_object_name = 'devices'


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView[DeviceModel, BaseModelForm[DeviceModel]]):
    """Device Create View."""

    http_method_names = ('get','post')

    model = DeviceModel
    fields = ('unique_name', 'serial_number', 'onboarding_protocol', 'domain')
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')

    @staticmethod
    def clean_device_name(device_name: str) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Args:
            device_name: The desired name of the new device.

        Returns:
            The device name if it passed the checks.
        """
        UniqueNameValidator(device_name)
        return device_name

    def form_valid(self, form: BaseModelForm[DeviceModel]) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS server credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        form_instance = form.instance
        onboarding_protocol = form.cleaned_data.get('onboarding_protocol')
        form_instance.onboarding_status = (
            DeviceModel.OnboardingStatus.NO_ONBOARDING
            if onboarding_protocol == DeviceModel.OnboardingStatus.NO_ONBOARDING
            else DeviceModel.OnboardingStatus.PENDING
        )
        return super().form_valid(form)


class DeviceDetailsView(DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel]):
    """Device Details View."""

    http_method_names = ('get',)

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/details.html'
    context_object_name = 'device'


class DeviceConfigureView(DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel]):
    """Device Configuration View."""

    http_method_names = ('get',)

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/configure.html'
    context_object_name = 'device'


class DeviceManualOnboardingIssueDomainCredentialView(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel], FormView[IssueDomainCredentialForm]
):
    """View to issue a new domain credential."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/onboarding/manual.html'
    form_class = IssueDomainCredentialForm

    def get_initial(self) -> dict[str, str]:
        """Gets the initial data for the form.

        Returns:
            Dictionary containing the initial form data.
        """
        initial = super().get_initial()
        domain_credential_issuer = self.get_object().get_domain_credential_issuer()
        return initial | domain_credential_issuer.get_fixed_values()

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: IssueDomainCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new domain credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        device = self.get_object()

        domain_credential_issuer = device.get_domain_credential_issuer()
        domain_credential_issuer.issue_domain_credential()
        domain_credential_issuer.save()
        domain_credential_issuer.device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
        domain_credential_issuer.device.save()

        messages.success(
            self.request,
            'Successfully issued a domain credential for device ' f'{domain_credential_issuer.device.unique_name}',
        )

        return super().form_valid(form)


class DeviceBaseCredentialDownloadView(DeviceContextMixin, DetailView, FormView[CredentialDownloadForm]):
    """View to download a password protected application credential in the desired format.
    
    Inherited by the domain and application credential download views."""

    http_method_names = ('get', 'post')

    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'
    is_browser_download = False

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data depending on the credential.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        credential = self.get_object().credential

        if self.model == IssuedDomainCredentialModel:
            if credential.credential_type == CredentialModel.CredentialTypeChoice.DOMAIN_CREDENTIAL:
                context['credential_type'] = CredentialModel.CredentialTypeChoice.DOMAIN_CREDENTIAL.name.replace(
                    '_', ' ').title()
            else:
                raise Http404('IssuedDomainCredentialModel has credential_type != DOMAIN_CREDENTIAL')
            domain_credential_issuer = self.get_object().device.get_domain_credential_issuer()
            context = context | domain_credential_issuer.get_fixed_values()

        if self.model == IssuedApplicationCertificateModel:
            if credential.credential_type == CredentialModel.CredentialTypeChoice.APPLICATION_CREDENTIAL:
                credential_type = IssuedApplicationCertificateModel.ApplicationCertificateType(
                    self.get_object().issued_application_certificate_type
                )
                context['credential_type'] = credential_type.name.replace('_', ' ').title() + ' Credential'
            else:
                raise Http404('IssuedApplicationCertificateModel has credential_type != APPLICATION_CREDENTIAL')
            application_credential_issuer = self.get_object().device.get_tls_client_credential_issuer()
            context = context | application_credential_issuer.get_fixed_values()
            context['common_name'] = self.object.credential.certificate.common_name

        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
        context['show_browser_dl'] = self.show_browser_dl
        context['is_browser_dl'] = self.is_browser_download
        return context

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: CredentialDownloadForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to start the download process of the desired file.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        password = form.cleaned_data['password'].encode()

        try:
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError:
            raise Http404

        credential_model = self.get_object().credential
        credential_serializer = credential_model.get_credential_serializer()
        credential_type = credential_model.credential_type
        credential_type_name = 'domain' # TODO: more generic

        if self.model == IssuedApplicationCertificateModel:
            credential_type = IssuedApplicationCertificateModel.ApplicationCertificateType(
                self.get_object().issued_application_certificate_type
            )

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential.p12')

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.ZIP.file_extension}'
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.TAR_GZ.file_extension}')

        else:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg)

        return cast('HttpResponse', response)


class DeviceDomainCredentialDownloadView(TpLoginRequiredMixin, DeviceBaseCredentialDownloadView):
    """View to download a password protected domain credential in the desired format."""

    model = IssuedDomainCredentialModel
    show_browser_dl = True


class DeviceApplicationCredentialDownloadView(TpLoginRequiredMixin, DeviceBaseCredentialDownloadView):
    """View to download a password protected application credential in the desired format."""

    model = IssuedApplicationCertificateModel
    show_browser_dl = False

# DeviceBrower Credential Download Views intentionally do not require authentication
class DeviceBrowserDomainCredentialDownloadView(DownloadTokenRequiredMixin, DeviceBaseCredentialDownloadView):

    model = IssuedDomainCredentialModel
    show_browser_dl = False
    is_browser_download = True


# class DeviceBrowserApplicationCredentialDownloadView(DeviceBaseCredentialDownloadView):

#     model = IssuedApplicationCertificateModel
#     show_browser_dl = False


class DeviceIssueTlsClientCredential(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel], FormView[IssueTlsClientCredentialForm]
):
    """View to issue a new TLS client credential."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsClientCredentialForm

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the form.

        Returns:
            Dictionary containing the initial form data.
        """
        initial = super().get_initial()
        tls_client_credential_issuer = self.get_object().get_tls_client_credential_issuer()
        initial.update(tls_client_credential_issuer.get_fixed_values())
        return initial

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: IssueTlsClientCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS client credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            The HttpResponse that will display the CLM summary view.
        """
        device = self.get_object()
        common_name = cast('str', form.cleaned_data.get('common_name'))
        validity = cast('int', form.cleaned_data.get('validity'))

        tls_client_issuer = device.get_tls_client_credential_issuer()
        tls_client_issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity)
        tls_client_issuer.save()
        messages.success(
            self.request, 'Successfully issued TLS Client credential device ' f'{tls_client_issuer.device.unique_name}'
        )
        return super().form_valid(form)


class DeviceIssueTlsServerCredential(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel], FormView[IssueTlsServerCredentialForm]
):
    """View to issue a new TLS server credential."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsServerCredentialForm

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the form.

        Returns:
            Dictionary containing the initial form data.
        """
        initial = super().get_initial()
        tls_server_credential_issuer = self.get_object().get_tls_server_credential_issuer()
        initial.update(tls_server_credential_issuer.get_fixed_values())
        return initial

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: IssueTlsServerCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS server credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            The HttpResponse that will display the CLM summary view.
        """
        device = self.get_object()

        common_name = cast('str', form.cleaned_data.get('common_name'))
        ipv4_addresses = cast('list[ipaddress.IPv4Address]', form.cleaned_data.get('ipv4_addresses'))
        ipv6_addresses = cast('list[ipaddress.IPv6Address]', form.cleaned_data.get('ipv6_addresses'))
        domain_names = cast('list[str]', form.cleaned_data.get('domain_names'))
        validity = cast('int', form.cleaned_data.get('validity'))

        if not common_name:
            raise Http404

        tls_server_credential_issuer = device.get_tls_server_credential_issuer()
        tls_server_credential_issuer.issue_tls_server_credential(
            common_name=common_name,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            domain_names=domain_names,
            validity_days=validity,
        )
        tls_server_credential_issuer.save()
        messages.success(
            self.request,
            'Successfully issued TLS Server credential device ' f'{tls_server_credential_issuer.device.unique_name}',
        )

        return super().form_valid(form)


class DeviceCertificateLifecycleManagementSummaryView(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel]
):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    context_object_name = 'device'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all GET requests.

        Args:
            request: The GET request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        device = self.get_object()

        device_domain_credential_table = DeviceDomainCredentialsTable(
            IssuedDomainCredentialModel.objects.filter(device=device)
        )
        device_application_certificates_table = DeviceApplicationCertificatesTable(
            IssuedApplicationCertificateModel.objects.filter(device=device)
        )

        self.extra_context['device_domain_credential_table'] = device_domain_credential_table
        self.extra_context['device_application_certificates_table'] = device_application_certificates_table
        return super().get(request, *args, **kwargs)


class DeviceRevocationView(DeviceContextMixin, TpLoginRequiredMixin, RedirectView):
    """Used to add the revocation not implemented error to the message system."""

    http_method_names = ('get',)
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:  # noqa: ARG002
        """Adds the revocation error message.

        Args:
            *args: Any positional arguments are disregarded.
            **kwargs: Any keyword arguments are disregarded.

        Returns:
            The url to redirect to, which is the HTTP_REFERER.
        """
        messages.error(self.request, 'Revocation is not yet implemented.')
        return cast('str', self.request.META.get('HTTP_REFERER', '/'))


class DeviceBrowserOnboardingOTPView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, RedirectView):
    """View to display the OTP for remote credential download (aka. browser onboarding)."""

    model = IssuedDomainCredentialModel
    template_name = 'devices/credentials/onboarding/browser/otp_view.html'
    redirection_view = 'devices:devices'
    context_object_name = 'credential'

    def get(self, request, *args: dict, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Renders a template view for displaying the OTP."""
        # TODO: checks: does this credential exist? Is it allowed to generate a new OTP for it? (maybe should be allowed only once)

        credential = self.get_object()
        device = credential.device
        cdm, _ = RemoteDeviceCredentialDownloadModel.objects.get_or_create(issued_credential_model=credential, device=device)

        context = {
            'device_name': device.unique_name,
            'device_id': device.id,
            'otp': cdm.get_otp_display(),
            'download_url': request.build_absolute_uri(reverse('devices:browser_login')),
        }

        return render(request, self.template_name, context)


class DeviceBrowserOnboardingCancelView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, RedirectView):
    """View to cancel the browser onboarding process and delete the associated RemoteDeviceCredentialDownloadModel."""

    model = IssuedDomainCredentialModel
    redirection_view = 'devices:domain_credential_download'
    context_object_name = 'credential'

    def get_redirect_url(self, *args: tuple, **kwargs: dict):
        pk = self.kwargs.get('pk')
        return reverse(self.redirection_view, kwargs={'pk': pk})

    def get(self, request, *args: tuple, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Cancels the browser onboarding process and deletes the associated RemoteDeviceCredentialDownloadModel."""
        credential = self.get_object()
        device = credential.device
        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential, device=device)
            cdm.delete()
            messages.info(request, 'The browser onboarding process was canceled.')
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            messages.error(request, 'The browser onboarding process was not found.')

        return redirect(self.get_redirect_url())


class DeviceOnboardingBrowserLoginView(FormView):
    """View to handle certificate download requests."""

    template_name = 'devices/credentials/onboarding/browser/login.html'
    form_class = BrowserLoginForm

    def fail(self):
        """On login failure, redirect back to the login page with an error message."""
        messages.error(self.request, _('The provided password is not valid.'))
        return redirect(self.request.path)

    def post(self, request, *args: tuple, **kwargs: dict) -> HttpResponse:
        """Handles POST request for browser login form submission."""
        form = BrowserLoginForm(request.POST)
        if not form.is_valid():
            return self.fail()

        cred_id = form.cleaned_data['cred_id']
        otp = form.cleaned_data['otp']
        try:
            credential_download = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=cred_id)
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            return self.fail()

        if not credential_download.check_otp(otp):
            return self.fail()

        token = credential_download.download_token
        url = f"{reverse('devices:browser_domain_credential_download', kwargs={'pk': cred_id})}?token={token}"
        return redirect(url)
