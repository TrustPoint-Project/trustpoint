from __future__ import annotations

from typing import TYPE_CHECKING
# from urllib.parse import quote

from django.views import View

from trustpoint.views import ContextDataMixin, TpLoginRequiredMixin, BulkDeleteView
from django.views.generic.base import RedirectView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView, CreateView, UpdateView
from django_tables2 import SingleTableView
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
# from django.core.files.uploadedfile import InMemoryUploadedFile
from django.contrib import messages
# from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect


from .models import CertificateModel, IssuingCaModel, DomainProfile
# RevokedCertificate

from .tables import CertificateTable, IssuingCaTable, DomainProfileTable
from .forms import (
    CertificateDownloadForm,
    IssuingCaAddMethodSelectForm,
    IssuingCaFileTypeSelectForm,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportOtherForm)
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


class DomainProfilesContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domain_profiles'


class DomainProfileTableView(DomainProfilesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Domain Profile Table View."""

    model = DomainProfile
    table_class = DomainProfileTable
    template_name = 'pki/domain_profiles/domain_profiles.html'


class DomainProfileCreateView(DomainProfilesContextMixin, TpLoginRequiredMixin, CreateView):

    model = DomainProfile
    template_name = 'pki/domain_profiles/add.html'
    fields = ['unique_name', 'url_path_segment', 'issuing_ca']
    success_url = reverse_lazy('pki:domain_profiles')
    ignore_url = reverse_lazy('pki:domain_profiles')


class DomainProfileUpdateView(DomainProfilesContextMixin, TpLoginRequiredMixin, UpdateView):

    model = DomainProfile
    template_name = 'pki/domain_profiles/add.html'
    fields = ['unique_name', 'issuing_ca']
    success_url = reverse_lazy('pki:domain_profiles')
    ignore_url = reverse_lazy('pki:domain_profiles')


class DomainProfileDetailView(DomainProfilesContextMixin, TpLoginRequiredMixin, DetailView):

    model = DomainProfile
    template_name = 'pki/domain_profiles/details.html'
    context_object_name = 'domain_profile'


class DomainProfilesBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = DomainProfile
    success_url = reverse_lazy('pki:domain_profiles')
    ignore_url = reverse_lazy('pki:domain_profiles')
    template_name = 'pki/domain_profiles/confirm_delete.html'
    context_object_name = 'domain_profiles'


# -------------------------------------------- Certificate revocation list  --------------------------------------------


class CRLDownloadView(View):
    """Revoked Certificates download view."""

    @staticmethod
    def download_ca_crl(self: CRLDownloadView, ca_id):
        try:
            issuing_ca = IssuingCaModel.objects.get(pk=ca_id)
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Issuing CA not found.'))
            return redirect('pki:issuing_cas')

        crl_data = issuing_ca.get_crl()
        if not crl_data:
            messages.warning(self, _('No CRL available for issuing CA %s.') % issuing_ca.unique_name)
            return redirect('pki:issuing_cas')
        response = HttpResponse(crl_data, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{issuing_ca.unique_name}.crl"'
        return response

    @staticmethod
    def download_domain_profile_crl(self: CRLDownloadView, id):
        try:
            domain_profile = DomainProfile.objects.get(pk=id)
        except IssuingCaModel.DoesNotExist:
            messages.error(self, _('Domain Profile not found.'))
            return redirect('pki:domain_profiles')

        crl_data = domain_profile.get_crl()
        if not crl_data:
            messages.warning(self, _('No CRL available for domain profile %s.') % domain_profile.unique_name)
            return redirect('pki:domain_profiles')
        response = HttpResponse(crl_data, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{domain_profile.unique_name}.crl"'
        return response


# ---------------------------------------------------- TrustStores  ----------------------------------------------------


class TrustStoresContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'truststores'


class TrustStoresTableView(TrustStoresContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates Table View."""

    # TODO: Create Truststore Model and modify this
    model = CertificateModel
    table_class = CertificateTable
    template_name = 'pki/truststores/truststores.html'



