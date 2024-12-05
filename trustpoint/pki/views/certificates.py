"""This module contains all views concerning the PKI -> Certificates section."""

from __future__ import annotations

from core.file_builder.certificate import CertificateArchiveFileBuilder, CertificateFileBuilder
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from django.http import Http404, HttpRequest, HttpResponse  # type: ignore[import-untyped]
from django.urls import reverse_lazy  # type: ignore[import-untyped]
from django.views.generic.base import RedirectView  # type: ignore[import-untyped]
from django.views.generic.detail import DetailView  # type: ignore[import-untyped]
from django.views.generic.list import ListView  # type: ignore[import-untyped]
from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from pki.models import CertificateModel
from pki.tables import CertificateTable
from trustpoint.views.base import PrimaryKeyListFromPrimaryKeyString, TpLoginRequiredMixin


class CertificatesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class PkiCertificatesContextMixin:
    """Mixin which adds some extra context for the PKI Views."""

    context_page_category = 'pki'
    context_page_name = 'certificates'


class CertificateTableView(PkiCertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates Table View."""

    model = CertificateModel
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'
    context_object_name = 'certificates'


class CertificateDetailView(PkiCertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    """The certificate detail view."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'


class CertificateDownloadView(PkiCertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    """View for downloading a single certificate."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download.html'
    context_object_name = 'certificate'

    def get(
        self, request: HttpRequest, pk: str | None = None, file_format: str | None = None, *args: tuple, **kwargs: dict
    ) -> HttpResponse:
        """HTTP GET Method.

        If only the certificate primary key are passed in the url, the download summary will be displayed.
        If value for file_format is also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pk: A string containing the certificate primary key.
            file_format: The format of the certificate to download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pk:
            raise Http404

        if file_format is None:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFileFormat(value=self.kwargs.get('file_format'))
        except Exception as exception:
            raise Http404 from exception

        certificate_serializer = CertificateModel.objects.get(pk=pk).get_certificate_serializer()
        file_bytes = CertificateFileBuilder.build(certificate_serializer, file_format=file_format_enum)

        response = HttpResponse(file_bytes, content_type=file_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificate{file_format_enum.file_extension}"'

        return response


class CertificateMultipleDownloadView(
    PkiCertificatesContextMixin, TpLoginRequiredMixin, PrimaryKeyListFromPrimaryKeyString, ListView
):
    """View for downloading multiple certificates at once as archived files."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download_multiple.html'
    context_object_name = 'certificates'

    def get_context_data(self, **kwargs: dict) -> dict:
        """Adding the part of the url to the context, that contains the certificate primary keys.

        This is used for the {% url }% tags in the template to download files.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
            dict: The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks_path'] = self.kwargs.get('pks')
        return context

    def get(
        self,
        request: HttpRequest,
        pks: str | None = None,
        file_format: None | str = None,
        archive_format: None | str = None,
        *args: tuple,
        **kwargs: dict,
    ) -> HttpResponse:
        """HTTP GET Method.

        If only certificate primary keys are passed in the url, the download summary will be displayed.
        If value for file_format and archive_format are also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pks: A string containing the certificate primary keys, e.g. 1/2/3/4/5
            file_format: The format of the archived certificate files.
            archive_format: The archive format that will be provided as download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pks:
            raise Http404

        if not file_format and not archive_format:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFileFormat(value=file_format)
        except Exception as exception:
            raise Http404 from exception

        try:
            archive_format_enum = ArchiveFormat(archive_format)
        except Exception as exception:
            raise Http404 from exception

        pks_list = self.get_pks_as_list(pks=pks)
        queryset = self.model.objects.filter(pk__in=pks_list)

        if len(pks_list) != len(queryset):
            raise Http404

        file_bytes = CertificateArchiveFileBuilder.build(
            certificate_serializers=[certificate_model.get_certificate_serializer() for certificate_model in queryset],
            file_format=file_format_enum,
            archive_format=archive_format_enum,
        )

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificates{archive_format_enum.file_extension}"'

        return response
