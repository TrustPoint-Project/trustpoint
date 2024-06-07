from trustpoint.views import BulkDeletionMixin, ContextDataMixin, Form, MultiFormView, TpLoginRequiredMixin
from django.views.generic.base import RedirectView
from django_tables2 import SingleTableView

from .models import TrustStore
from .tables import TrustStoreTable


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