from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from trustpoint.views import ContextDataMixin, TpLoginRequiredMixin, BulkDeleteView
from django.views.generic.base import RedirectView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView, CreateView, UpdateView, DeleteView
from django_tables2 import SingleTableView
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import transaction
from django.http import HttpResponse


from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509


from .models import Certificate, CertificateRevocationList, IssuingCa, DomainProfile
from .tables import CertificateTable, IssuingCaTable, DomainProfileTable
from .forms import CertificateDownloadForm, IssuingCaAddMethodSelectForm, IssuingCaAddFileImportForm
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

    model = Certificate
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'


class CertificateDetailView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    model = Certificate
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'


class CertificateDownloadView(CertificatesContextMixin, TpLoginRequiredMixin, ListView):
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

    model = IssuingCa
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'


class IssuingCaAddMethodSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
    template_name = 'pki/issuing_cas/add/method_select.html'
    form_class = IssuingCaAddMethodSelectForm


class IssuingCaAddFileImportView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportForm
    success_url = reverse_lazy('pki:issuing_cas')

    def form_valid(self, form) -> HttpResponse:
        unique_name = form.cleaned_data['unique_name']

        private_key_password = form.cleaned_data['private_key_password'].encode()
        if not private_key_password:
            private_key_password = None

        private_key_file = self.request.FILES['private_key_file']
        if not isinstance(private_key_file, InMemoryUploadedFile):
            return self.form_invalid(form=form)
        private_key_file = private_key_file.read()

        loaded_private_key, loaded_certificates = self._load_keyfile(private_key_file, private_key_password)

        if 'cert_chain' in self.request.FILES:
            cert_chain = self.request.FILES['cert_chain']
            if not isinstance(cert_chain, InMemoryUploadedFile):
                return self.form_invalid(form=form)

            loaded_certificates.extend(self._load_cert_chain(cert_chain.read()))

        if 'issuing_ca_certificate' in self.request.FILES:
            issuing_ca_certificate = self.request.FILES['issuing_ca_certificate']
            if not isinstance(issuing_ca_certificate, InMemoryUploadedFile):
                return self.form_invalid(form=form)

            loaded_certificates.append(self._load_issuing_ca_certificate(issuing_ca_certificate.read()))

        issuing_ca_cert = self._get_issuing_ca_certificate(
            loaded_private_key=loaded_private_key,
            loaded_certificates=loaded_certificates)
        full_cert_chain = self._get_cert_chain(issuing_ca_cert=issuing_ca_cert, certs=loaded_certificates)

        self._save_to_db(unique_name=unique_name, certs=full_cert_chain, private_key=loaded_private_key)

        return super().form_valid(form=form)

    @staticmethod
    @transaction.atomic
    def _save_to_db(
            unique_name: str,
            certs: list[x509.Certificate],
            private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> None:

        # TODO: create method, make atomic transaction
        issuing_ca_cert_db = Certificate.save_certificate_chain_and_key(
            certs=certs,
            priv_key=private_key)

        issuing_ca_db = IssuingCa(issuing_ca_certificate=issuing_ca_cert_db, unique_name=unique_name)
        issuing_ca_db.save()

    @staticmethod
    def _get_issuing_ca_certificate(
            loaded_private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
            loaded_certificates: list[x509.Certificate]) -> x509.Certificate:
        loaded_public_key_spki = loaded_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        for cert in loaded_certificates:
            cert_public_key_spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if cert_public_key_spki == loaded_public_key_spki:
                return cert
            raise RuntimeError('Failed to find an Issuing CA certificate.')

    @staticmethod
    def _check_certificate_is_issuing_ca(cert: x509.Certificate) -> None:
        # TODO: check extensions etc.
        pass

    @staticmethod
    def _get_cert_chain(issuing_ca_cert: x509.Certificate, certs: list[x509.Certificate]) -> list[x509.Certificate]:
        # TODO: proper path validation
        cert_chain = [issuing_ca_cert]

        if issuing_ca_cert.subject.public_bytes() == issuing_ca_cert.issuer.public_bytes():
            return cert_chain

        current_issued_cert = issuing_ca_cert
        for cert in certs:
            if cert.subject.public_bytes() == cert.issuer.public_bytes():
                cert_chain.append(cert)
                break
            if current_issued_cert.issuer.public_bytes() == cert.subject.public_bytes():
                cert_chain.append(cert)
                current_issued_cert = cert
        else:
            raise RuntimeError('Failed to construct full certificate chain.')

        return cert_chain

    @staticmethod
    def _load_cert_chain(cert_chain_bytes: bytes) -> list[x509.Certificate]:
        try:
            return x509.load_pem_x509_certificates(cert_chain_bytes)
        except Exception:
            pass

        raise RuntimeError('Failed to load certificate chain file.')

    @staticmethod
    def _load_issuing_ca_certificate(cert_bytes: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(cert_bytes)
        except Exception:
            pass

        raise RuntimeError('Failed to load Issuing CA certificate.')

    @staticmethod
    def _load_keyfile(
            private_key_file: bytes,
            private_key_password: None | bytes = None
    ) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, list[x509.Certificate]]:

        certs = []
        # try loading PKCS#12 file
        try:
            p12 = pkcs12.load_pkcs12(private_key_file, private_key_password)
            private_key = p12.key
            if p12.cert:
                certs.append(p12.cert.certificate)
            if p12.additional_certs:
                for cert in p12.additional_certs:
                    certs.append(cert.certificate)

            return private_key, certs

        except Exception:
            # TODO: check what could be raised and catch it
            pass

        try:
            private_key = serialization.load_pem_private_key(private_key_file, password=private_key_password)
            return private_key, []
        except Exception:
            pass

        try:
            private_key = serialization.load_der_private_key(private_key_file, password=private_key_password)
            return private_key, []
        except Exception:
            pass

        raise RuntimeError(f'Unable to load private key.')


class IssuingCaDetailView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):
    model = IssuingCa
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = IssuingCa
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
    fields = ['unique_name', 'issuing_ca']
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


# -------------------------------------------------- Certificate revocation list  --------------------------------------------------


class CRLListView(TpLoginRequiredMixin, SingleTableView):
    """Revoked Certificates List View."""

    #from onboarding.crypto_backend import CryptoBackend # ?

    model = CertificateRevocationList
    table_class = None
    template_name = 'pki/revoked_certificates/revoked_certificates.html'

    @staticmethod
    def download_crl(self: IssuingCa, ca_id):
        try:
            issuing_ca = IssuingCa.objects.get(pk=ca_id)
            crl_data = issuing_ca.generate_crl()
            response = HttpResponse(crl_data, content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{quote('a')}"'
            return response
        except IssuingCa.DoesNotExist:
            return HttpResponse("Issuing CA not found", status=404)
