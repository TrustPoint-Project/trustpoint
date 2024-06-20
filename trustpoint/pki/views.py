from __future__ import annotations

from typing import TYPE_CHECKING

from trustpoint.views import ContextDataMixin, Form, MultiFormView, TpLoginRequiredMixin
from django.views.generic.base import RedirectView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django_tables2 import SingleTableView
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.http import HttpResponse


from .models import Certificate
from .tables import CertificateTable
from .forms import CertificateDownloadForm
from .files import (
    CertificateFileContainer,
    CertificateChainIncluded,
    CertificateFileFormat,
    CertificateFileGenerator
)


if TYPE_CHECKING:
    from typing import Any
    from django.db.models import QuerySet


# -------------------------------------------------- Certificate Views -------------------------------------------------

class CertificatesContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'certificates'


class CertificatesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CertificateTableView(CertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates Table View."""

    model = Certificate
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'


class CertificateDetailView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    model = Certificate
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'


class CertificateDownloadView(TpLoginRequiredMixin, ListView):
    model = Certificate
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
        """Gets the configured ignore_url.

        If no ignore_url is configured, it will return the success_url.

        Returns:
            str:
                The ignore_url or success_url.

        """
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    @staticmethod
    def get_download_response(
            certs: list[Certificate],
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
        response['Content-Disposition'] = f'inline; filename={filename}'
        return response

    def get(self, request, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles HTTP GET requests.

        Args:
            request (HTTPRequest):
                The HTTP request object.
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            HttpResponse:
                The response corresponding to the HTTP GET request.
        """

        form = CertificateDownloadForm(request.GET)
        if form.is_valid():
            form.clean()
            certs = Certificate.objects.filter(id__in=self.get_pks())
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

    def get_pks(self) -> list[str]:
        """Gets the primary keys for the objects to delete.

        Expects a string containing the primary keys delimited by forward slashes.
        Cannot start with a forward slash.
        A trailing forward slash is optional.

        Returns:
            list[str]:
                A list of the primary keys as strings.
        """
        return self.kwargs['pks'].split('/')

    def get_queryset(self) -> QuerySet | None:  # noqa: ARG002
        """Gets the queryset of the objects to be deleted.

        Returns:
            QuerySet | None:
                The queryset of the objects to be deleted.
                None, if one or more primary keys do not have corresponding objects in the database or
                if the primary key list pks is empty.
        """
        if self.queryset:
            return self.queryset

        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset
