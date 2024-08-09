from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.views import View
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormView, UpdateView
from django.views.generic.list import ListView
from django_tables2 import SingleTableView

from trustpoint.views import BulkDeleteView, ContextDataMixin, TpLoginRequiredMixin

from .files import CertificateChainIncluded, CertificateFileContainer, CertificateFileFormat, CertificateFileGenerator
from .forms import (
    CertificateDownloadForm,
    DomainCreateForm,
    DomainUpdateForm,
    IssuingCaAddFileImportOtherForm,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddMethodSelectForm,
    IssuingCaFileTypeSelectForm,
    TrustStoreAddForm,
)
from .models import CertificateModel, DomainModel, IssuingCaModel, TrustStoreModel
from .pki_message import PkiEstSimpleEnrollRequestMessage
from .request_handler.est import CaRequestHandlerFactory

# RevokedCertificate
from .tables import CertificateTable, DomainTable, IssuingCaTable, TrustStoreTable

if TYPE_CHECKING:
    from typing import Any
    from django.db.models import QuerySet


# -------------------------------------------------- Certificate Views -------------------------------------------------


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


class CertificateDetailView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'


class CertificateDownloadView(CertificatesContextMixin, TpLoginRequiredMixin, ListView):
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
        response['Content-Disposition'] = f'inline; filename={filename}'
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

    def get_pks(self) -> list[str]:
        return self.kwargs['pks'].split('/')

    def get_queryset(self) -> QuerySet | None:
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


class IssuingCaContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'


class IssuingCaTableView(IssuingCaContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Issuing CA Table View."""

    model = IssuingCaModel
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'


class IssuingCaAddMethodSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
    template_name = 'pki/issuing_cas/add/method_select.html'
    form_class = IssuingCaAddMethodSelectForm

    def form_valid(self, form) -> HttpResponse:
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))

        if method_select and method_select == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))


class IssuingCaAddFileTypeSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
    template_name = 'pki/issuing_cas/add/file_type_select.html'
    form_class = IssuingCaFileTypeSelectForm

    def form_valid(self, form) -> HttpResponse:
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        if method_select == 'pkcs_12':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-pkcs12'))
        elif method_select == 'other':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-other'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))


class IssuingCaAddFileImportPkcs12View(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportPkcs12Form
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaAddFileImportOtherView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportOtherForm
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaDetailView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):
    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'issuing_cas'


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Domain Table View."""

    model = DomainModel
    table_class = DomainTable
    template_name = 'pki/domains/domain.html'


class DomainCreateView(DomainContextMixin, TpLoginRequiredMixin, CreateView):

    model = DomainModel
    template_name = 'pki/domains/add.html'
    form_class = DomainCreateForm
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainUpdateView(DomainContextMixin, TpLoginRequiredMixin, UpdateView):

    model = DomainModel
    template_name = 'pki/domains/add.html'
    form_class = DomainUpdateForm
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainDetailView(DomainContextMixin, TpLoginRequiredMixin, DetailView):

    model = DomainModel
    template_name = 'pki/domains/details.html'
    context_object_name = 'domain'


class DomainBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = DomainModel
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')
    template_name = 'pki/domains/confirm_delete.html'
    context_object_name = 'domains'


# -------------------------------------------- Certificate revocation list  --------------------------------------------


class CRLDownloadView(View):
    """Revoked Certificates download view."""

    @staticmethod
    def download_ca_crl(self: CRLDownloadView, ca_id):
        try:
            issuing_ca = IssuingCaModel.objects.get(pk=ca_id).get_issuing_ca()
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Issuing CA not found.'))
            return redirect('pki:issuing_cas')

        crl_data = issuing_ca.get_crl()
        if not crl_data:
            messages.warning(self, _('No CRL available for issuing CA %s.') % issuing_ca.get_ca_name())
            return redirect('pki:issuing_cas')
        response = HttpResponse(crl_data, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{issuing_ca.get_ca_name()}.crl"'
        return response

    @staticmethod
    def generate_ca_crl(self: CRLDownloadView, ca_id):
        try:
            issuing_ca = IssuingCaModel.objects.get(pk=ca_id).get_issuing_ca()
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Issuing CA not found.'))
            return redirect('pki:issuing_cas')

        if issuing_ca.generate_crl():
            messages.info(self, _('CRL generated'))
        else:
            messages.warning(self, _('CRL could not be generated'))
        return redirect('pki:issuing_cas')

    @staticmethod
    def download_domain_crl(self: CRLDownloadView, id_):
        try:
            domain = DomainModel.objects.get(pk=id_)
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Domain not found.'))
            return redirect('pki:domains')

        crl_data = domain.get_crl()
        if not crl_data:
            messages.warning(self, _('No CRL available for domain %s.') % domain.unique_name)
            return redirect('pki:domains')
        response = HttpResponse(crl_data, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{domain.unique_name}.crl"'
        return response

    @staticmethod
    def generate_domain_crl(self: CRLDownloadView, id_):
        try:
            domain = DomainModel.objects.get(pk=id_)
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Domain not found.'))
            return redirect('pki:domains')

        if domain.generate_crl():
            messages.info(self, _('CRL generated'))
        else:
            messages.warning(self, _('CRL could not be generated'))
        return redirect('pki:domains')


# ---------------------------------------------------- TrustStores  ----------------------------------------------------


class TrustStoresContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'truststores'


class TrustStoresTableView(TrustStoresContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates Table View."""

    # TODO: Create Truststore Model and modify this
    model = TrustStoreModel
    table_class = TrustStoreTable
    template_name = 'pki/truststores/truststores.html'


class TrustStoreAddView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/truststores/add.html'
    form_class = TrustStoreAddForm
    success_url = reverse_lazy('pki:truststores')


# --------------------------------------------------- PKI Endpoints  ---------------------------------------------------


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollView(View):
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):

        # TODO: content-length
        pki_request = PkiEstSimpleEnrollRequestMessage(
            mimetype=request.headers.get('Content-Type'),
            content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
            domain_unique_name=self.kwargs.get('domain'),
            raw_request=request.read()
        )

        if pki_request.is_invalid:
            return pki_request.invalid_response.to_django_http_response()

        request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
        return request_handler.process_request().to_django_http_response()
