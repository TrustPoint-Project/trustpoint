"""This module contains all views concerning the devices application."""
from __future__ import annotations

import zipfile

from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView    # type: ignore[import-untyped]
from django.urls import reverse_lazy, reverse   # type: ignore[import-untyped]
from django.views.generic.base import RedirectView  # type: ignore[import-untyped]
from django.views.generic.detail import BaseDetailView, DetailView  # type: ignore[import-untyped]
from django.http import FileResponse, Http404   # type: ignore[import-untyped]

from django.shortcuts import redirect
from trustpoint.views.base import TpLoginRequiredMixin
from core.validator.field import UniqueNameValidator
from devices.models import DeviceModel
from devices.tables import DeviceTable
from typing import TYPE_CHECKING
import io
from core.ca.domain_credential import DomainCredentialBuilder
from cryptography.hazmat.primitives.serialization import pkcs12
from core.file_builder.archiver import Archiver
from core.file_builder.enum import ArchiveFormat

if TYPE_CHECKING:
    from typing import ClassVar
    from django.http import HttpResponse    # type: ignore[import-untyped]


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


class ManualOnboardingView(DeviceContextMixin, DetailView):

    http_method_names = ['get']

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/onboarding/manual.html'


class ManualOnboardingDownloadView(DeviceContextMixin, BaseDetailView):

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

        domain_credential_builder = DomainCredentialBuilder()
        domain_credential_builder.set_issuing_ca_credential(
            device.domain.issuing_ca.credential.get_credential_serializer())
        domain_credential_builder.set_domain_name('abc')
        domain_credential_builder.set_device_serial_number('xyz')
        domain_credential = domain_credential_builder.build()

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

        # TODO(AlexHx8472): Add credential to issued domain credentials.
        # TODO(AlexHx8472): Add auto-gen password and display it in frontend.

        return response
