from trustpoint.views import BulkDeletionMixin, ContextDataMixin, Form, MultiFormView, TpLoginRequiredMixin
from django.views.generic.base import RedirectView
from django_tables2 import SingleTableView

from .models import Certificate, TrustStore
from .tables import CertificateTable, TrustStoreTable


# -------------------------------------------------- Certificate Views -------------------------------------------------

class CertificatesContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'certificates'


class CertificatesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CertificateListView(CertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates List View."""

    model = Certificate
    table_class = CertificateTable
    template_name = 'pki/certificates/certificates.html'


# -------------------------------------------------- TrustStore Views --------------------------------------------------


class CredentialsContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'certificates'


class CredentialsRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CredentialListView(CertificatesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Certificates List View."""

    # def get_queryset(self):
    #     return

    model = Certificate
    table_class = CertificateTable
    template_name = 'pki/credentials/credentials.html'


# -------------------------------------------------- TrustStore Views --------------------------------------------------

class TruststoreContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Truststores pages."""

    context_page_category = 'pki'
    context_page_name = 'truststores'


class TruststoreRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Truststore application: Truststore"""

    permanent = False
    pattern_name = 'pki:truststores'


class TruststoreListView(TruststoreContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Issuing CAs List View."""

    model = TrustStore
    table_class = TrustStoreTable
    template_name = 'pki/truststores/truststores.html'
