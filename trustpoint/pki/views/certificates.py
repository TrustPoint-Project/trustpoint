from __future__ import annotations

from typing import TYPE_CHECKING


from django.http import Http404, HttpResponse
from django.urls import reverse_lazy


from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView
from django_tables2 import SingleTableView

from pki.file_builder.certificate import CertificateFileBuilder
from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin, PrimaryKeyFromUrlToQuerysetMixin
from pki.download.certificate import CertificateDownloadResponseBuilder, MultiCertificateDownloadResponseBuilder
from pki.models import CertificateModel
from pki.tables import CertificateTable
from pki.file_builder import CertificateFileFormat


if TYPE_CHECKING:
    from django.db.models import QuerySet


class CertificatesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CertificatesContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'certificates'


class CertificateTableView(CertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates Table View."""

    model = CertificateModel
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'
    context_object_name = 'certificates'


class IssuedCertificatesTableView(CertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):

    model = CertificateModel
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'
    context_object_name = 'certificates'

    def get_queryset(self) -> None | QuerySet:
        pk = self.kwargs.get('pk')
        if not pk:
            return None

        try:
            issuing_ca_cert = CertificateModel.objects.get(pk=pk)
        except CertificateModel.DoesNotExist:
            return None

        if not issuing_ca_cert.is_ca:
            return None

        self.extra_context = {'issuing_ca_cert': issuing_ca_cert}

        return issuing_ca_cert.issued_certificate_references.all()


class CertificateDetailView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'


class CertificateDownloadView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download.html'
    context_object_name = 'certificate'

    def get(self, *args: tuple, **kwargs: dict) -> HttpResponse:
        pk = self.kwargs.get('pk')
        if not pk:
            raise Http404

        file_format = self.kwargs.get('file_format')
        if file_format is None:
            return super().get(*args, **kwargs)

        try:
            file_format = CertificateFileFormat(self.kwargs.get('file_format'))
        except Exception:
            raise Http404

        file_bytes = CertificateFileBuilder.build(pk, file_format=file_format)

        response = HttpResponse(file_bytes, content_type=file_format.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificate{file_format.file_extension}"'

        return response


class CertificateMultipleDownloadView(
    CertificatesContextMixin,
    TpLoginRequiredMixin,
    PrimaryKeyFromUrlToQuerysetMixin,
    ListView):

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download_multiple.html'
    context_object_name = 'certificates'

    def get(self, *args, **kwargs):
        self.extra_context = {'pks_url_path': self.get_pks_path()}
        pks = self.get_pks()
        file_format = self.kwargs.get('file_format')
        archive_format = self.kwargs.get('archive_format')


        if file_format is None and archive_format is None:
            return super().get(*args, **kwargs)

        if file_format is None or archive_format is None:
            raise Http404




