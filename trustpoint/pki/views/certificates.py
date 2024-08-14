from __future__ import annotations

from idlelib.query import Query
from typing import TYPE_CHECKING


from django.http import HttpResponse, Http404
from django.shortcuts import redirect
from django.urls import reverse_lazy


from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView
from django_tables2 import SingleTableView

from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin, PrimaryKeyFromUrlToQuerysetMixin
from pki.download.certificate import CertificateDownloadResponseBuilder
from ..files import CertificateChainIncluded, CertificateFileContainer, CertificateFileFormat, CertificateFileGenerator
from ..forms import CertificateDownloadForm
from ..models import CertificateModel


from ..tables import CertificateTable

if TYPE_CHECKING:
    from typing import Any
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
    context_object_name = 'cert'

    def get(self, *args, **kwargs):
        file_format = self.kwargs.get('file_format')
        if file_format is None:
            return super().get(*args, **kwargs)

        pk = self.kwargs.get('pk')

        return CertificateDownloadResponseBuilder(pk, file_format).as_django_http_response()


class CertificateMultipleDownloadView(
    CertificatesContextMixin,
    TpLoginRequiredMixin,
    PrimaryKeyFromUrlToQuerysetMixin,
    ListView):

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download.html'
    context_object_name = 'certs'

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = CertificateDownloadForm()
        context['cert_count'] = len(self.get_pks())
        return context

    def get_ignore_url(self) -> str:
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    @staticmethod
    def get_download_response(
            certs: list[CertificateModel],
            cert_file_container: str,
            cert_chain_incl: str,
            cert_file_format: str) -> HttpResponse:

        cert_file_container = CertificateFileContainer(cert_file_container)
        cert_chain_incl = CertificateChainIncluded(cert_chain_incl)
        cert_file_format = CertificateFileFormat(cert_file_format)
        file_content, filename = CertificateFileGenerator.generate(
            certs=certs,
            cert_file_container=cert_file_container,
            cert_chain_incl=cert_chain_incl,
            cert_file_format=cert_file_format
        )
        response = HttpResponse(file_content, content_type=cert_file_format.mime_type)
        response['Content-Disposition'] = f'attachment; filename={filename}'
        return response

    def get(self, request, *args: Any, **kwargs: Any) -> HttpResponse:
        form = CertificateDownloadForm(request.GET)
        if form.is_valid():
            form.clean()
            certs = CertificateModel.objects.filter(id__in=self.get_pks())
            cert_file_container = form.cleaned_data['cert_file_container']
            cert_chain_incl = form.cleaned_data['cert_chain_incl']
            cert_file_format = form.cleaned_data['cert_file_format']

            return self.get_download_response(
                certs=certs,
                cert_file_container=cert_file_container,
                cert_chain_incl=cert_chain_incl,
                cert_file_format=cert_file_format
            )

        if self.get_queryset() is None:
            return redirect(self.get_ignore_url())

        return super().get(request, *args, **kwargs)
