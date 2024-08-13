from __future__ import annotations


from django.urls import reverse_lazy

from django.views.generic.edit import FormView
from django_tables2 import SingleTableView

from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin


from ..forms import TrustStoreAddForm
from ..models import TrustStoreModel
from ..tables import TrustStoreTable


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


class TrustStoreAddView(TrustStoresContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/truststores/add.html'
    form_class = TrustStoreAddForm
    success_url = reverse_lazy('pki:truststores')