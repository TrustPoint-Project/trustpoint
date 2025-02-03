"""This module contains all views concerning the PKI -> Truststore section."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.shortcuts import get_object_or_404

from core.file_builder.certificate import CertificateArchiveFileBuilder, CertificateFileBuilder
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect  # type: ignore[import-untyped]
from django.urls import reverse_lazy, reverse  # type: ignore[import-untyped]
from django.views.generic.base import RedirectView  # type: ignore[import-untyped]
from django.views.generic.detail import DetailView  # type: ignore[import-untyped]
from django.views.generic.edit import FormView
from django.views.generic.list import ListView  # type: ignore[import-untyped]

from pki.forms import TruststoreAddForm
from pki.models import DomainModel
from pki.models.truststore import TruststoreModel
from trustpoint.views.base import PrimaryKeyListFromPrimaryKeyString, TpLoginRequiredMixin

if TYPE_CHECKING:
    from typing import ClassVar


class TruststoresRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Truststores application: Truststores."""

    permanent = False
    pattern_name = 'pki:truststores'


class TruststoresContextMixin:
    """Mixin which adds some extra context for the PKI Views."""

    extra_context: ClassVar = {'page_category': 'pki', 'page_name': 'truststores'}

class TruststoreTableView(TruststoresContextMixin, ListView):
    """Truststore Table View."""

    model = TruststoreModel
    template_name = 'pki/truststores/truststores.html'  # Template file
    context_object_name = 'truststores'
    paginate_by = 5  # Number of items per page

    def get_queryset(self):
        queryset = TruststoreModel.objects.all()

        # Get sort parameter (e.g., "name" or "-name")
        sort_param = self.request.GET.get("sort", "unique_name")  # Default to "unique_name"
        return queryset.order_by(sort_param)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get current sorting column
        sort_param = self.request.GET.get("sort", "unique_name")  # Default to "unique_name"
        is_desc = sort_param.startswith("-")  # Check if sorting is descending
        current_sort = sort_param.lstrip("-")  # Remove "-" to get column name
        next_sort = f"-{current_sort}" if not is_desc else current_sort  # Toggle sorting

        # Pass sorting details to the template
        context.update({
            "current_sort": current_sort,
            "is_desc": is_desc,
        })
        return context


class TruststoreCreateView(TruststoresContextMixin, TpLoginRequiredMixin, FormView):
    """View for creating a new Truststore."""

    model = TruststoreModel
    form_class = TruststoreAddForm
    template_name = 'pki/truststores/add/file_import.html'
    ignore_url = reverse_lazy('pki:truststores')

    def form_valid(self, form):
        method_select = form.cleaned_data.get('method_select')
        truststore = form.cleaned_data['truststore']
        print(truststore.id)
        domain_id = self.kwargs.get("pk")

        if domain_id:
            print(f"Redirecting to DevID registration page with Truststore ID: {truststore.id}")
            return HttpResponseRedirect(reverse('pki:devid_registration_create-with_truststore_id', kwargs={'pk': domain_id, 'truststore_id': truststore.id}))

        print("No domain ID provided, redirecting to Truststore add page.")
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

        certificate_serializer = TruststoreModel.objects.get(pk=pk).get_serializer()
        file_bytes = CertificateFileBuilder.build(certificate_serializer, file_format=file_format_enum)

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

        file_bytes = CertificateArchiveFileBuilder.build(
            certificate_serializers=[certificate_model.get_serializer() for certificate_model in self.queryset],
            file_format=file_format_enum,
            archive_format=archive_format_enum,
        )

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="truststores{archive_format_enum.file_extension}"'

        return response
