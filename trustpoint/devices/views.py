"""This module contains all views concerning the devices application."""
from __future__ import annotations


from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView, FormView  # type: ignore[import-untyped]
from django.urls import reverse_lazy, reverse   # type: ignore[import-untyped]
from django.views.generic.base import RedirectView, TemplateView # type: ignore[import-untyped]
from django.views.generic.detail import BaseDetailView, DetailView  # type: ignore[import-untyped]
from django.http import FileResponse, Http404   # type: ignore[import-untyped]
from django.contrib import messages # type: ignore[import-untyped]
from django.shortcuts import redirect, render   # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]

from core.serializer import CredentialSerializer
from devices.forms import IssueDomainCredentialForm, CredentialDownloadForm, IssueTlsClientCredentialForm, IssueTlsServerCredentialForm
from trustpoint.views.base import TpLoginRequiredMixin
from core.validator.field import UniqueNameValidator
from devices.models import IssuedDomainCredentialModel
from devices.tables import DeviceTable, DeviceDomainCredentialsTable, DeviceApplicationCertificatesTable
from typing import TYPE_CHECKING
import io
from core.file_builder.enum import ArchiveFormat
from devices.models import DeviceModel, IssuedApplicationCertificateModel

from pki.models.credential import CredentialModel

if TYPE_CHECKING:
    from typing import ClassVar
    from django.http import HttpResponse    # type: ignore[import-untyped]
    from django.forms import BaseModelForm  # type: ignore[import-untyped]


class DevicesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the devices application."""

    permanent = False
    pattern_name = 'devices:devices'


class DeviceContextMixin:
    """Mixin which adds context_data for the Devices -> Devices pages."""

    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'devices'}


class DeviceTableView(DeviceContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Endpoint Profiles List View."""

    model = DeviceModel
    table_class = DeviceTable
    template_name = 'devices/devices.html'
    context_object_name = 'devices'


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    model = DeviceModel
    fields = ['unique_name', 'serial_number', 'onboarding_protocol', 'domain']
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')

    @staticmethod
    def clean_device_name(device_name: str) -> str:
        UniqueNameValidator(device_name)
        return device_name

    def form_valid(self, form: BaseModelForm) -> HttpResponse:
        form_instance = form.instance
        onboarding_protocol = form.cleaned_data.get('onboarding_protocol')
        form_instance.onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING \
            if onboarding_protocol == DeviceModel.OnboardingStatus.NO_ONBOARDING \
            else DeviceModel.OnboardingStatus.PENDING
        return super().form_valid(form)


class DeviceDetailsView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/details.html'
    context_object_name = 'device'


class DeviceConfigureView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/configure.html'
    context_object_name = 'device'


class DeviceManualOnboardingIssueDomainCredentialView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get', 'post']

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/onboarding/manual.html'
    form_class = IssueDomainCredentialForm

    def get_initial(self) -> dict:
        initial = super().get_initial()
        domain_credential_issuer = self.get_object().get_domain_credential_issuer()
        return initial | domain_credential_issuer.get_fixed_values()

    def post(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()

        domain_credential_issuer = device.get_domain_credential_issuer()
        domain_credential_issuer.issue_domain_credential()
        domain_credential_issuer.save()
        domain_credential_issuer.device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
        domain_credential_issuer.device.save()

        messages.success(
            self.request,
            'Successfully issued a domain credential for device '
            f'{domain_credential_issuer.device.unique_name}')

        return redirect(
            reverse_lazy(
                'devices:certificate_lifecycle_management',
                kwargs={'pk': device.id}))


class DeviceDomainCredentialDownloadView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get', 'post']

    model = IssuedDomainCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'

    def get_context_data(self, **kwargs: dict) -> dict:
        context = super().get_context_data(**kwargs)
        credential = self.get_object().credential
        if credential.credential_type == CredentialModel.CredentialTypeChoice.DOMAIN_CREDENTIAL:
            context['credential_type'] = CredentialModel.CredentialTypeChoice.DOMAIN_CREDENTIAL.name.replace(
                '_', ' ').title()
        else:
            raise Http404('Nope. Fail!')

        domain_credential_issuer = self.get_object().device.get_domain_credential_issuer()
        context = context | domain_credential_issuer.get_fixed_values()
        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
        return context

    def get(self, request, *args, **kwargs):
        """Handles GET requests, which will display the download view and form."""
        self.object = self.get_object()
        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        """Handles POST requests and processes the form received."""
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form):
        password = self.request.POST.get('password').encode()

        try:
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError:
            raise Http404

        credential_model = self.get_object().credential
        credential_serializer = credential_model.get_credential_serializer()

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-domain-credential.p12')

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint-domain-credential{ArchiveFormat.ZIP.file_extension}'
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint-domain-credential{ArchiveFormat.TAR_GZ.file_extension}')

        else:
            raise Http404

        return response


class DeviceApplicationCredentialDownloadView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get', 'post']

    model = IssuedApplicationCertificateModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'

    def get_context_data(self, **kwargs: dict) -> dict:
        credential = self.get_object().credential
        context = super().get_context_data(**kwargs)
        if credential.credential_type == CredentialModel.CredentialTypeChoice.APPLICATION_CREDENTIAL:
            credential_type = IssuedApplicationCertificateModel.ApplicationCertificateType(
                self.get_object().issued_application_certificate_type
            )
            context['credential_type'] = credential_type.name.replace('_', ' ').title() + ' Credential'
        else:
            raise Http404
        application_credential_issuer = self.get_object().device.get_tls_client_credential_issuer()
        context = context | application_credential_issuer.get_fixed_values()
        context['common_name'] = self.object.credential.certificate.common_name
        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
        return context

    def get(self, request, *args: tuple, **kwargs: dict) -> HttpResponse:
        """Handles GET requests, which will display the download view and form."""
        self.object = self.get_object()
        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def post(self, request, *args: tuple, **kwargs: dict) -> HttpResponse | FileResponse:
        """Handles POST requests and processes the form received."""
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form) -> HttpResponse | FileResponse:
        self.object = self.get_object()

        password = self.request.POST.get('password').encode()

        try:
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError:
            raise Http404

        credential_model = self.get_object().credential
        credential_serializer = credential_model.get_credential_serializer()

        credential_type = IssuedApplicationCertificateModel.ApplicationCertificateType(
            self.get_object().issued_application_certificate_type
        )
        credential_type_name = credential_type.name.replace('_', '-').lower()

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
            raise Http404('Unknown file format found.')

        return response


class DeviceIssueTlsClientCredential(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get', 'post']

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsClientCredentialForm

    def get_initial(self) -> dict:
        initial = super().get_initial()
        tls_client_credential_issuer = self.get_object().get_tls_client_credential_issuer()
        return initial | tls_client_credential_issuer.get_fixed_values()

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

    def post(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()
        form = self.get_form()

        if form.is_valid():
            common_name = form.cleaned_data.get('common_name')
            validity = form.cleaned_data.get('validity')
            if not common_name:
                raise Http404

            tls_client_issuer = device.get_tls_client_credential_issuer()
            tls_client_issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity)
            tls_client_issuer.save()
            messages.success(
                self.request,
                'Successfully issued TLS Client credential device '
                f'{tls_client_issuer.device.unique_name}')

            return redirect(
                reverse_lazy(
                    'devices:certificate_lifecycle_management',
                    kwargs={'pk': device.id}))

        else:
            return self.form_invalid(form)


class DeviceIssueTlsServerCredential(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get', 'post']

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsServerCredentialForm

    def get_initial(self) -> dict:
        initial = super().get_initial()
        tls_server_credential_issuer = self.get_object().get_tls_server_credential_issuer()
        return initial | tls_server_credential_issuer.get_fixed_values()

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

    def post(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()
        form = self.get_form()

        if form.is_valid():

            common_name = form.cleaned_data.get('common_name')
            ipv4_addresses = form.cleaned_data.get('ipv4_addresses')
            ipv6_addresses = form.cleaned_data.get('ipv6_addresses')
            domain_names = form.cleaned_data.get('domain_names')
            validity = form.cleaned_data.get('validity')

            if not common_name:
                raise Http404

            tls_server_credential_issuer = device.get_tls_server_credential_issuer()
            tls_server_credential_issuer.issue_tls_server_credential(
                common_name=common_name,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                domain_names=domain_names,
                validity_days=validity
            )
            tls_server_credential_issuer.save()
            messages.success(
                self.request,
                'Successfully issued TLS Server credential device '
                f'{tls_server_credential_issuer.device.unique_name}')

            return redirect(
                reverse_lazy(
                    'devices:certificate_lifecycle_management',
                    kwargs={'pk': device.id}))

        else:
            return self.form_invalid(form)


class DeviceCertificateLifecycleManagementSummaryView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ['get']

    model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    context_object_name = 'device'


    def get(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()

        device_domain_credential_table = DeviceDomainCredentialsTable(IssuedDomainCredentialModel.objects.filter(device=device))
        device_application_certificates_table = DeviceApplicationCertificatesTable(
            IssuedApplicationCertificateModel.objects.filter(device=device))

        self.extra_context['device_domain_credential_table'] = device_domain_credential_table
        self.extra_context['device_application_certificates_table'] = device_application_certificates_table
        return super().get(*args, **kwargs)


class DeviceRevocationView(DeviceContextMixin, TpLoginRequiredMixin, RedirectView):

    http_method_names = ['get']
    permanent = False

    def get_redirect_url(self, *args: tuple, **kwargs: dict) -> str:
        messages.error(self.request, 'Revocation is not yet implemented.')
        referer = self.request.META.get('HTTP_REFERER', '/')
        return referer
