from __future__ import annotations


from django.urls import reverse_lazy

from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView

from django.http import Http404
from django_tables2 import SingleTableView

from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin, PrimaryKeyFromUrlToQuerysetMixin
from pki.download.certificate import CertificateDownloadResponseBuilder, MultiCertificateDownloadResponseBuilder


from pki.forms import TrustStoreAddForm, TruststoresDownloadForm
from pki.models import TrustStoreModel, CertificateModel
from pki.tables import TrustStoreTable


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


class TrustStoresDetailView(TrustStoresContextMixin, TpLoginRequiredMixin, DetailView):
    """ TrustStore Details View"""
    model = TrustStoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    # table_class = TrustStoreDetailsTable
    template_name = 'pki/truststores/details.html'
    context_object_name = 'truststore'


class TrustStoresDownloadView(TrustStoresContextMixin, TpLoginRequiredMixin, DetailView):

    model = TrustStoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download.html'
    context_object_name = 'truststore'
    short: bool = None

    def get(self, *args, **kwargs):
        file_format = self.kwargs.get('file_format')
        file_content = self.kwargs.get('file_content')
        if file_format is None and file_content is None:
            return super().get(*args, **kwargs)

        if file_format is None or file_content is None:
            raise Http404

        pk = self.kwargs.get('pk')

        return CertificateDownloadResponseBuilder(pk, file_format, file_content).as_django_http_response()


class TrustStoresMultipleDownloadView(
    TrustStoresContextMixin,
    TpLoginRequiredMixin,
    PrimaryKeyFromUrlToQuerysetMixin,
    ListView):

    model = CertificateModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download_multiple.html'
    context_object_name = 'truststores'

    def get(self, *args, **kwargs):
        self.extra_context = {'pks_url_path': self.get_pks_path()}

        file_format = self.kwargs.get('file_format')
        file_content = self.kwargs.get('file_content')
        archive_format = self.kwargs.get('archive_format')
        if file_format is None and file_content is None  and archive_format is None:
            return super().get(*args, **kwargs)

        if file_format is None or file_content is None or archive_format is None:
            raise Http404

        pks = self.get_pks()

        return MultiCertificateDownloadResponseBuilder(
            pks=pks,
            file_format=file_format,
            file_content=file_content,
            archive_format=archive_format).as_django_http_response()

