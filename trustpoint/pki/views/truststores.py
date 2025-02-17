"""This module contains all views concerning the PKI -> Truststore section."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.shortcuts import get_object_or_404
from django.views.generic import DeleteView

from core.file_builder.certificate import CertificateCollectionArchiveFileBuilder, CertificateCollectionBuilder
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy, reverse
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from django.contrib import messages
from django.utils.translation import gettext_lazy as _

from pki.forms import TruststoreAddForm
from pki.models import DomainModel
from pki.models.truststore import TruststoreModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import PrimaryKeyListFromPrimaryKeyString, SortableTableMixin, TpLoginRequiredMixin

if TYPE_CHECKING:
    from typing import ClassVar


class TruststoresRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Truststores application: Truststores."""

    permanent = False
    pattern_name = 'pki:truststores'


class TruststoresContextMixin:
    """Mixin which adds some extra context for the PKI Views."""

    extra_context: ClassVar = {'page_category': 'pki', 'page_name': 'truststores'}

class TruststoreTableView(TruststoresContextMixin, TpLoginRequiredMixin, SortableTableMixin, ListView):
    """Truststore Table View."""

    model = TruststoreModel
    template_name = 'pki/truststores/truststores.html'
    context_object_name = 'truststores'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class TruststoreCreateView(TruststoresContextMixin, TpLoginRequiredMixin, FormView):
    """View for creating a new Truststore."""

    model = TruststoreModel
    form_class = TruststoreAddForm
    template_name = 'pki/truststores/add/file_import.html'
    ignore_url = reverse_lazy('pki:truststores')

    def form_valid(self, form):
        truststore = form.cleaned_data['truststore']
        domain_id = self.kwargs.get("pk")

        if domain_id:
            return HttpResponseRedirect(reverse('pki:devid_registration_create-with_truststore_id', kwargs={'pk': domain_id, 'truststore_id': truststore.id}))

        return HttpResponseRedirect(reverse('pki:truststores'))

    def get_success_url(self):
        """You could still use a success URL here if needed"""
        return reverse_lazy('pki:truststores')

    def get_context_data(self, **kwargs):
        """Include domain in context only if pk is present."""
        context = super().get_context_data(**kwargs)
        pk = self.kwargs.get("pk")
        if pk:
            context["domain"] = get_object_or_404(DomainModel, id=pk)
        return context

class TruststoreDetailView(TruststoresContextMixin, TpLoginRequiredMixin, DetailView):
    """The truststore detail view."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/details.html'
    context_object_name = 'truststore'

class TruststoreDownloadView(TruststoresContextMixin, TpLoginRequiredMixin, DetailView):
    """View for downloading a single truststore."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download.html'
    context_object_name = 'truststore'

    def get(
        self, request: HttpRequest, pk: str | None = None, file_format: str | None = None, *args: tuple, **kwargs: dict
    ) -> HttpResponse:
        """HTTP GET Method.

        If only the certificate primary key are passed in the url, the download summary will be displayed.
        If value for file_format is also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pk: A string containing the certificate primary key.
            file_format: The format of the certificate to download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pk:
            raise Http404

        if file_format is None:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFileFormat(value=self.kwargs.get('file_format'))
        except Exception as exception:
            raise Http404 from exception

        certificate_serializer = TruststoreModel.objects.get(pk=pk).get_certificate_collection_serializer()

        file_bytes = CertificateCollectionBuilder.build(
            certificate_serializer,
            file_format=file_format_enum)

        response = HttpResponse(file_bytes, content_type=file_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="truststore{file_format_enum.file_extension}"'

        return response

class TruststoreMultipleDownloadView(
    TruststoresContextMixin, TpLoginRequiredMixin, PrimaryKeyListFromPrimaryKeyString, ListView
):
    """View for downloading multiple truststores at once as archived files."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download_multiple.html'
    context_object_name = 'truststores'

    def get_context_data(self, **kwargs: dict) -> dict:
        """Adding the part of the url to the context, that contains the truststores primary keys.

        This is used for the {% url }% tags in the template to download files.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
            dict: The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks_path'] = self.kwargs.get('pks')
        return context

    def get(
        self,
        request: HttpRequest,
        pks: str | None = None,
        file_format: None | str = None,
        archive_format: None | str = None,
        *args: tuple,
        **kwargs: dict,
    ) -> HttpResponse:
        """HTTP GET Method.

        If only certificate primary keys are passed in the url, the download summary will be displayed.
        If value for file_format and archive_format are also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pks: A string containing the certificate primary keys, e.g. 1/2/3/4/5
            file_format: The format of the archived certificate files.
            archive_format: The archive format that will be provided as download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pks:
            raise Http404

        pks_list = self.get_pks_as_list(pks=pks)
        self.queryset = self.model.objects.filter(pk__in=pks_list)

        if len(pks_list) != len(self.queryset):
            raise Http404

        if not file_format and not archive_format:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFileFormat(value=file_format)
        except Exception as exception:
            raise Http404 from exception

        try:
            archive_format_enum = ArchiveFormat(archive_format)
        except Exception as exception:
            raise Http404 from exception

        certificate_collection_serializers = [
            TruststoreModel.objects.get(pk=pk).get_certificate_collection_serializer() for pk in pks_list
        ]

        file_bytes = CertificateCollectionArchiveFileBuilder.build(
            certificate_collection_serializers=certificate_collection_serializers,
            file_format=file_format_enum,
            archive_format=archive_format_enum
        )

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="truststores{archive_format_enum.file_extension}"'

        return response

class TruststoreDeleteView(TruststoresContextMixin, TpLoginRequiredMixin, DeleteView):
    """View to delete a DevID Registration."""
    model = TruststoreModel
    template_name = 'pki/truststores/confirm_delete.html'
    success_url = reverse_lazy('pki:truststores')

    def delete(self, request, *args, **kwargs):
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response

class TruststoreBulkDeleteView(TruststoresContextMixin, TpLoginRequiredMixin, View):
    template_name = 'pki/truststores/confirm_delete.html'

    def post(self, request, *args, **kwargs):
        truststore_ids = request.POST.getlist('truststore_ids')
        truststores = TruststoreModel.objects.filter(id__in=truststore_ids)

        if 'confirm' in request.POST:
            deleted_count, _ = truststores.delete()
            messages.success(request, _(f'{deleted_count} Truststore(s) deleted successfully.'))
            return redirect('pki:truststores')

        return render(request, self.template_name, {'truststores': truststores})
