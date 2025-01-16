"""This module contains all views concerning the devices application."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, cast

from core.file_builder.enum import ArchiveFormat
from core.serializer import CredentialSerializer
from core.validator.field import UniqueNameValidator
from django.contrib import messages
from django.forms import BaseModelForm
from django.http import FileResponse, Http404, HttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormView
from django.db.models import Q

# TODO(AlexHx8472): Remove django_tables2 dependency, and thus remove the type: ignore[misc]
from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from pki.models.credential import CredentialModel

from devices.issuer import LocalTlsClientCredentialIssuer, LocalTlsServerCredentialIssuer, LocalDomainCredentialIssuer

from devices.forms import (
    CredentialDownloadForm,
    IssueDomainCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
)
from devices.models import DeviceModel, IssuedCredentialModel
from devices.tables import DeviceApplicationCertificatesTable, DeviceDomainCredentialsTable, DeviceTable
from trustpoint.views.base import TpLoginRequiredMixin

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
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

    http_method_names = ('get',)

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
        device = self.get_object()
        initial.update(LocalDomainCredentialIssuer.get_fixed_values(device=device, domain=device.domain))
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

    def form_valid(self, form: IssueDomainCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new domain credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        device = self.get_object()

        domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=device.domain)
        _ = domain_credential_issuer.issue_domain_credential()
        messages.success(
            self.request,
            'Successfully issued domain credential for device ' f'{domain_credential_issuer.device.unique_name}'
        )
        return super().form_valid(form)
#
class DeviceApplicationCredentialDownloadView(
    DeviceContextMixin,
    TpLoginRequiredMixin,
    DetailView[IssuedCredentialModel],
    FormView[CredentialDownloadForm],
):
    """View to download a password protected application credential in the desired format.

    Note that a redirect occurs directly after the download starts. However, this is implemented in JavaScript.
    """

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data depending on the credential.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        issued_credential = self.get_object()
        credential = issued_credential.credential
        application_credential_value = IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value
        if issued_credential.issued_credential_type != application_credential_value:
            raise Http404

        context['common_name'] = credential.certificate.common_name
        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
        context['issued_credential'] = issued_credential
        return context

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

    def form_valid(self, form: CredentialDownloadForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to start the download process of the desired file.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        self.object = self.get_object()

        password = form.cleaned_data['password'].encode()

        try:
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg) from ValueError

        credential_model = self.get_object().credential

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint--credential.p12',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint--credential{ArchiveFormat.ZIP.file_extension}',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint--credential{ArchiveFormat.TAR_GZ.file_extension}',
            )

        else:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg)

        return cast('HttpResponse', response)

class DeviceDomainCredentialDownloadView(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[IssuedCredentialModel], FormView[CredentialDownloadForm]
):
    """View to download a password protected domain credential in the desired format.

    Note that a redirect occurs directly after the download starts. However, this is implemented in JavaScript.
    """

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data depending on the credential.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        issued_credential = self.get_object()
        domain_credential_value = IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value
        if issued_credential.issued_credential_type != domain_credential_value:
            raise Http404

        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
        context['issued_credential'] = issued_credential
        return context

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
            err_msg = _('Unknown file format.')
            raise Http404(err_msg) from ValueError

        credential_model = self.get_object().credential

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename='trustpoint-domain-credential.p12',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint-domain-credential{ArchiveFormat.ZIP.file_extension}',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_model.get_credential_serializer().as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint-domain-credential{ArchiveFormat.TAR_GZ.file_extension}',
            )

        else:
            raise Http404

        return cast('HttpResponse', response)


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
        device = self.get_object()
        initial.update(LocalTlsClientCredentialIssuer.get_fixed_values(device=device, domain=device.domain))
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        form_kwargs = super().get_form_kwargs()
        form_kwargs.update({'device': self.get_object()})
        return form_kwargs

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

        tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=device.domain)
        _ = tls_client_issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity)
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
        device = self.get_object()
        initial.update(LocalTlsServerCredentialIssuer.get_fixed_values(device=device, domain=device.domain))
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        form_kwargs = super().get_form_kwargs()
        form_kwargs.update({'device': self.get_object()})
        return form_kwargs

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

        tls_server_credential_issuer = LocalTlsServerCredentialIssuer(device=device, domain=device.domain)
        _ = tls_server_credential_issuer.issue_tls_server_credential(
            common_name=common_name,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            domain_names=domain_names,
            validity_days=validity,
        )
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
            IssuedCredentialModel.objects.filter(
                Q(device=device) &
                Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value)
            )
        )
        device_application_certificates_table = DeviceApplicationCertificatesTable(
            IssuedCredentialModel.objects.filter(
                Q(device=device) &
                Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value)
            )
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
