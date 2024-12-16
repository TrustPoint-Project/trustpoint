"""This module contains all views concerning the devices application."""
from __future__ import annotations


from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView, FormView  # type: ignore[import-untyped]
from django.urls import reverse_lazy, reverse   # type: ignore[import-untyped]
from django.views.generic.base import RedirectView, TemplateView  # type: ignore[import-untyped]
from django.views.generic.detail import BaseDetailView, DetailView  # type: ignore[import-untyped]
from django.http import FileResponse, Http404   # type: ignore[import-untyped]
from django.contrib import messages # type: ignore[import-untyped]
from django.shortcuts import redirect   # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]

from devices.forms import IssueTlsClientCredentialForm
from trustpoint.views.base import TpLoginRequiredMixin
from core.validator.field import UniqueNameValidator
from devices.models import DeviceModel, IssuedDomainCredentialModel, IssuedApplicationCertificateModel
from devices.tables import DeviceTable, DeviceDomainCredentialsTable, DeviceApplicationCertificatesTable
from typing import TYPE_CHECKING
import io
from core.file_builder.archiver import Archiver
from core.file_builder.enum import ArchiveFormat
from cryptography.x509.oid import NameOID
from devices.models import DeviceModel, IssuedApplicationCertificateModel

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
        if form.cleaned_data.get('onboarding_protocol') == DeviceModel.OnboardingProtocol.NO_ONBOARDING:
            form_instance.onboarding_status =  DeviceModel.OnboardingStatus.NO_ONBOARDING
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


class ManualOnboardingView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ['get']

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/onboarding/manual.html'


class ManualOnboardingDownloadView(DeviceContextMixin, TpLoginRequiredMixin, BaseDetailView):

    http_method_names = ['get']

    model = DeviceModel
    context_object_name = 'device'
    redirect_url_name = 'devices:devices'

    @staticmethod
    def _get_file_response(data: io.BytesIO, content_type: str, filename: str) -> FileResponse:
        return FileResponse(data, content_type=content_type, as_attachment=True, filename=filename)

    def get(self, *args, **kwargs) -> FileResponse:
        device = self.get_object()
        if not device.domain:
            raise Http404
        if not device.domain.issuing_ca:
            raise Http404
        if device.onboarding_status != DeviceModel.OnboardingStatus.PENDING:
            raise Http404

        domain_credential = device.issue_domain_credential()

        format_ = self.kwargs['format']
        if format_ == 'pkcs12':
            response = FileResponse(
                io.BytesIO(domain_credential.as_pkcs12()),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-domain-credential-{device.unique_name}.p12')

        elif format_ == 'zip':
            zip_archive = Archiver.archive(
                data_to_archive={
                    'domain_credential_private_key.pem': domain_credential.credential_private_key.as_pkcs8_pem(),
                    'domain_credential_certificate.pem': domain_credential.credential_certificate.as_pem(),
                    'domain_credential_certificate_chain.pem': domain_credential.additional_certificates.as_pem()
                },
                archive_format=ArchiveFormat.ZIP
            )

            response = self._get_file_response(
                data=io.BytesIO(zip_archive),
                content_type=ArchiveFormat.ZIP.mime_type,
                filename=f'trustpoint-domain-credential-{device.unique_name}{ArchiveFormat.ZIP.file_extension}')

        elif format_ == 'tar_gz':
            tar_gz_archive = Archiver.archive(
                data_to_archive={
                    'domain_credential_private_key.pem': domain_credential.credential_private_key.as_pkcs8_pem(),
                    'domain_credential_certificate.pem': domain_credential.credential_certificate.as_pem(),
                    'domain_credential_certificate_chain.pem': domain_credential.additional_certificates.as_pem()
                },
                archive_format=ArchiveFormat.TAR_GZ
            )

            response = self._get_file_response(
                data=io.BytesIO(tar_gz_archive),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                filename=f'trustpoint-domain-credential-{device.unique_name}{ArchiveFormat.TAR_GZ.file_extension}')

        else:
            raise Http404

        device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
        device.save()

        return response


class ManualOnboardingSummaryView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ['get']
    model = DeviceModel
    template_name = 'devices/onboarding/manual_summary.html'
    context_object_name = 'device'

    def get(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()
        if device.onboarding_status != DeviceModel.OnboardingStatus.ONBOARDED:
            raise Http404

        messages.success(self.request, _(f'Device {device.unique_name} successfully onboarded.'))

        return redirect(reverse_lazy('devices:devices'))


class DeviceCertificateLifecycleManagementSummaryView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ['get']
    model = DeviceModel
    template_name = 'devices/certificate_lifecycle_management/summary.html'
    context_object_name = 'device'


    def get(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()

        device_domain_credential_table = DeviceDomainCredentialsTable(IssuedDomainCredentialModel.objects.filter(device=device))
        device_application_certificates_table = DeviceApplicationCertificatesTable(
            IssuedApplicationCertificateModel.objects.filter(device=device))

        self.extra_context['device_domain_credential_table'] = device_domain_credential_table
        self.extra_context['device_application_certificates_table'] = device_application_certificates_table
        return super().get(*args, **kwargs)


class DeviceIssueTlsClientCredentialView(DeviceContextMixin, TpLoginRequiredMixin, DetailView, FormView):

    http_method_names = ['get']
    model = DeviceModel
    template_name = 'devices/certificate_lifecycle_management/tls_client.html'
    form_class = IssueTlsClientCredentialForm
    context_object_name = 'device'

    def get_success_url(self) -> str:
        return reverse_lazy('devices:clm', kwargs={'pk': self.get_object().id})

    def get_initial(self):
        device = self.get_object()
        return {
            'common_name': '',
            'pseudonym': 'Trustpoint TLS-Client Certificate',
            'serial_number': device.serial_number,
            'dn_qualifier': f'trustpoint.{device.unique_name}.{device.domain}',
            'validity': 10
        }


class DeviceDownloadIssuedApplicationTlsClientCredential(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    model = DeviceModel
    http_method_names = ['get', 'post']
    template_name = 'devices/certificate_lifecycle_management/download.html'
    context_object_name = 'device'

    @staticmethod
    def _get_file_response(data: io.BytesIO, content_type: str, filename: str) -> FileResponse:
        return FileResponse(data, content_type=content_type, as_attachment=True, filename=filename)

    def post(self, *args: tuple, **kwargs: dict) -> HttpResponse | FileResponse:
        device = self.get_object()
        if not device.domain:
            raise Http404
        if not device.domain.issuing_ca:
            raise Http404

        common_name = self.request.POST.get('common_name')
        validity_days = self.request.POST.get('validity')

        self.extra_context['common_name'] = common_name
        self.extra_context['validity'] = validity_days
        return super().get(*args, **kwargs)

    def get(self, *args: tuple, **kwargs: dict) -> FileResponse:
        common_name = self.kwargs.get('common_name')
        validity_days = self.kwargs.get('validity')
        format_ = self.kwargs.get('format')
        device = self.get_object()

        distinguished_name = {
            NameOID.COMMON_NAME: common_name,
            NameOID.PSEUDONYM: 'Trustpoint TLS-Client Certificate',
            NameOID.SERIAL_NUMBER: device.serial_number,
            NameOID.DN_QUALIFIER: f'trustpoint.{device.unique_name}.{device.domain}'
        }

        credential = device.issue_application_credential(
            subject=distinguished_name,
            validity_days=validity_days,
            certificate_type=IssuedApplicationCertificateModel.ApplicationCertificateType.TLS_CLIENT
        )

        if format_ == 'pkcs12':
            response = FileResponse(
                io.BytesIO(credential.as_pkcs12()),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-domain-credential-{device.unique_name}.p12')

        elif format_ == 'zip':
            zip_archive = Archiver.archive(
                data_to_archive={
                    'tls_client_credential_private_key.pem': credential.credential_private_key.as_pkcs8_pem(),
                    'tls_client_credential_certificate.pem': credential.credential_certificate.as_pem(),
                    'tls_client_credential_certificate_chain.pem': credential.additional_certificates.as_pem()
                },
                archive_format=ArchiveFormat.ZIP
            )

            response = self._get_file_response(
                data=io.BytesIO(zip_archive),
                content_type=ArchiveFormat.ZIP.mime_type,
                filename=f'trustpoint-tls_client-credential-{device.unique_name}{ArchiveFormat.ZIP.file_extension}')

        elif format_ == 'tar_gz':
            tar_gz_archive = Archiver.archive(
                data_to_archive={
                    'tls_client_credential_private_key.pem': credential.credential_private_key.as_pkcs8_pem(),
                    'tls_client_credential_certificate.pem': credential.credential_certificate.as_pem(),
                    'tls_client_credential_certificate_chain.pem': credential.additional_certificates.as_pem()
                },
                archive_format=ArchiveFormat.TAR_GZ
            )

            response = self._get_file_response(
                data=io.BytesIO(tar_gz_archive),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                filename=f'trustpoint-tls_client-credential-{device.unique_name}{ArchiveFormat.TAR_GZ.file_extension}')

        else:
            raise Http404

        return response


class DeviceSuccessfulApplicationIssuanceRedirectView(DeviceContextMixin, TpLoginRequiredMixin, BaseDetailView):

    http_method_names = ['get']
    model = DeviceModel
    context_object_name = 'device'

    def get(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        device = self.get_object()

        messages.success(
            self.request,
            _(f'Device {device.unique_name} successfully issued an application certificate.'))

        return redirect(reverse_lazy('devices:devices'))