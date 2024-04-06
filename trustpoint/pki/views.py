"""Contains views specific to the PKI application."""


from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormMixin, UpdateView
from django.views.generic.list import BaseListView, MultipleObjectTemplateResponseMixin
from django_tables2 import SingleTableView
from util.x509.credentials import CredentialUploadHandler

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from trustpoint.views import BulkDeletionMixin, ContextDataMixin, Form, MultiFormView, TpLoginRequiredMixin

from .forms import IssuingCaLocalP12FileForm, IssuingCaLocalPemFileForm
from .models import EndpointProfile, IssuingCa, RootCa
from .tables import EndpointProfileTable, IssuingCaTable, RootCaTable

if TYPE_CHECKING:
    from typing import Any

    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse

    from .forms import IssuingCaUploadForm


# -------------------------------------------------- EndpointProfiles --------------------------------------------------


class IndexView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI application: Endpoint Profiles."""

    permanent = False
    pattern_name = 'pki:endpoint_profiles'


class EndpointProfilesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Endpoint Profiles application: Endpoint Profiles."""

    permanent = False
    pattern_name = 'pki:endpoint_profiles'


class EndpointProfilesContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Endpoint Profiles pages."""

    context_page_category = 'pki'
    context_page_name = 'endpoint_profiles'


class EndpointProfilesListView(EndpointProfilesContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Endpoint Profiles List View."""

    model = EndpointProfile
    table_class = EndpointProfileTable
    template_name = 'pki/endpoint_profiles/endpoint_profiles.html'


class EndpointProfilesDetailView(EndpointProfilesContextMixin, TpLoginRequiredMixin, DetailView):
    """Detail view for Endpoint Profiles."""

    model = EndpointProfile
    pk_url_kwarg = 'pk'
    template_name = 'pki/endpoint_profiles/details.html'

    def get_context_data(self: IssuingCaDetailView, **kwargs: Any) -> dict:
        """Adds the certificates and unique_name of the CA to the context if available.

        Args:
            **kwargs (Any): Keyword arguments. These are passed to super().get_context_data(**kwargs).

        Returns:
            dict:
                The context to be used for the view.
        """
        context = super().get_context_data(**kwargs)
        obj = self.get_object()
        if obj.issuing_ca is None:
            context['no_issuing_ca'] = '—'
            return context

        with default_storage.open(obj.issuing_ca.p12.name, 'rb') as f:
            certs_json = CredentialUploadHandler.parse_and_normalize_p12(f.read()).full_cert_chain_as_dict()

        context['certs'] = certs_json
        context['unique_name'] = obj.issuing_ca.unique_name
        return context


class EndpointProfilesBulkDeleteView(
    EndpointProfilesContextMixin,
    MultipleObjectTemplateResponseMixin,
    BulkDeletionMixin,
    FormMixin,
    TpLoginRequiredMixin,
    BaseListView,
):
    """View that allows bulk deletion of Endpoint Profiles.

    This view expects a path variable pks containing string with all primary keys separated by forward slashes /.
    It cannot start with a forward slash, however a trailing forward slash is optional.
    If one or more primary keys do not have a corresponding object in the database, the user will be redirected
    to the ignore_url.
    """

    model = EndpointProfile
    success_url = reverse_lazy('pki:endpoint_profiles')
    ignore_url = reverse_lazy('pki:endpoint_profiles')
    template_name = 'pki/endpoint_profiles/confirm_delete.html'
    context_object_name = 'objects'

    def get_ignore_url(self: EndpointProfilesBulkDeleteView) -> str:
        """Gets the get the configured ignore_url.

        If no ignore_url is configured, it will return the success_url.

        Returns:
            str:
                The ignore_url or success_url.

        """
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    def get_pks(self: EndpointProfilesBulkDeleteView) -> list[str]:
        """Gets the primary keys for the objects to delete.

        Expects a string containing the primary keys delimited by forward slashes.
        Cannot start with a forward slash.
        A trailing forward slash is optional.

        Returns:
            list[str]:
                A list of the primary keys as strings.
        """
        return self.kwargs['pks'].split('/')

    def get_queryset(self: EndpointProfilesBulkDeleteView, *args: Any, **kwargs: Any) -> QuerySet | None:  # noqa: ARG002
        """Gets the queryset of the objects to be deleted.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            QuerySet | None:
                The queryset of the objects to be deleted.
                None, if one or more primary keys do not have corresponding objects in the database or
                if the primary key list pks is empty.
        """
        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset

    def get(self: EndpointProfilesBulkDeleteView, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles HTTP GET requests.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            HttpResponse:
                The response corresponding to the HTTP GET request.
        """
        if self.get_queryset() is None:
            return redirect(self.get_ignore_url())

        return super().get(*args, **kwargs)


class CreateEndpointProfileView(EndpointProfilesContextMixin, TpLoginRequiredMixin, CreateView):
    """Endpoint Profile Create View."""

    model = EndpointProfile
    fields = ['unique_endpoint', 'issuing_ca']  # noqa: RUF012
    template_name = 'pki/endpoint_profiles/add.html'
    success_url = reverse_lazy('pki:endpoint_profiles')


class UpdateEndpointProfileView(EndpointProfilesContextMixin, TpLoginRequiredMixin, UpdateView):
    """Endpoint Profile Update View."""

    model = EndpointProfile
    fields = ['unique_endpoint', 'issuing_ca']                                                  # noqa: RUF012
    template_name = 'pki/endpoint_profiles/update.html'
    success_url = reverse_lazy('pki:endpoint_profiles')

# ----------------------------------------------------- RootCas -----------------------------------------------------

class RootCasContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'root_cas'


class RootCasRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:root_cas'


class RootCaListView(RootCasContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Root CAs List View."""

    model = RootCa
    table_class = RootCaTable
    template_name = 'pki/root_cas/root_cas.html'

class CreateRootCaView(RootCasContextMixin, TpLoginRequiredMixin, CreateView):
    """Root CA Create View."""

    model = RootCa
    fields = ['unique_name', 'common_name', 'not_valid_before', 'not_valid_after', 'ca_type']  # noqa: RUF012
    template_name = 'pki/root_cas/add.html'
    success_url = reverse_lazy('pki:root_cas')

    def generate_cert_from_model(self, root_ca_instance, passphrase):
        if root_ca_instance.ca_type == 'RSA2048':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        elif root_ca_instance.ca_type == 'SECP256R1':
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
        elif root_ca_instance.ca_type == 'SECP384R1':
            private_key = ec.generate_private_key(
                ec.SECP384R1()
            )
        else:
            raise ValueError("Unsupported algorithm type")

        # Prepare certificate subject and issuer from RootCa instance
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, root_ca_instance.common_name),
        ])

        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            root_ca_instance.not_valid_before
        ).not_valid_after(
            root_ca_instance.not_valid_after
        ).sign(private_key, hashes.SHA256())

        # Create a PKCS#12 (P12) archive
        p12 = pkcs12.serialize_key_and_certificates(
            b"mykeycert", private_key, certificate, None, BestAvailableEncryption(passphrase)
        )

        return p12

    # TODO(Florian): Hardcoded enrollment code for self signed root CA
    def form_valid(self, form):
        new_root_ca = form.save()

        passphrase = b"foo123"
        p12_token = self.generate_cert_from_model(new_root_ca, passphrase)

        p12_filename = f"media/{new_root_ca.unique_name}.p12"
        with open(p12_filename, "wb") as f:
            f.write(p12_token)

        # Continue with the standard form_valid processing, including redirecting to success_url
        return super().form_valid(form)

class RootCaDetailView(RootCasContextMixin, TpLoginRequiredMixin, DetailView):
    """Detail view for Root CAs."""

    model = RootCa
    pk_url_kwarg = 'pk'
    template_name = 'pki/root_cas/details.html'

    def get_context_data(self: RootCaDetailView, **kwargs: Any) -> dict:
        """Adds the certificates and unique_name to the context.

        Args:
            **kwargs (Any): Keyword arguments. These are passed to super().get_context_data(**kwargs).

        Returns:
            dict:
                The context to be used for the view.
        """
        context = super().get_context_data(**kwargs)

        #TODO(Florian): Hardcoded enrollment code for self signed root CA
        with default_storage.open(f"{self.get_object().unique_name}.p12", 'rb') as f:
            certs_json = CredentialUploadHandler.parse_and_normalize_p12(f.read(), b"foo123").full_cert_chain_as_dict()

        context['certs'] = certs_json
        context['unique_name'] = self.get_object().unique_name
        return context

class RootCaBulkDeleteView(
    RootCasContextMixin,
    MultipleObjectTemplateResponseMixin,
    BulkDeletionMixin,
    FormMixin,
    TpLoginRequiredMixin,
    BaseListView,
):
    """View that allows bulk deletion of Root CAs.

    This view expects a path variable pks containing string with all primary keys separated by forward slashes /.
    It cannot start with a forward slash, however a trailing forward slash is optional.
    If one or more primary keys do not have a corresponding object in the database, the user will be redirected
    to the ignore_url.
    """

    model = RootCa
    success_url = reverse_lazy('pki:root_cas')
    ignore_url = reverse_lazy('pki:root_cas')
    template_name = 'pki/root_cas/confirm_delete.html'
    context_object_name = 'objects'

    def get_ignore_url(self: RootCaBulkDeleteView) -> str:
        """Gets the get the configured ignore_url.

        If no ignore_url is configured, it will return the success_url.

        Returns:
            str:
                The ignore_url or success_url.

        """
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    def get_pks(self: RootCaBulkDeleteView) -> list[str]:
        """Gets the primary keys for the objects to delete.

        Expects a string containing the primary keys delimited by forward slashes.
        Cannot start with a forward slash.
        A trailing forward slash is optional.

        Returns:
            list[str]:
                A list of the primary keys as strings.
        """
        return self.kwargs['pks'].split('/')

    def get_queryset(self: RootCaBulkDeleteView, *args: Any, **kwargs: Any) -> QuerySet | None:  # noqa: ARG002
        """Gets the queryset of the objects to be deleted.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            QuerySet | None:
                The queryset of the objects to be deleted.
                None, if one or more primary keys do not have corresponding objects in the database or
                if the primary key list pks is empty.
        """
        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset

    def get(self: RootCaBulkDeleteView, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles HTTP GET requests.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            HttpResponse:
                The response corresponding to the HTTP GET request.
        """
        if self.get_queryset() is None:
            return redirect(self.get_ignore_url())

        return super().get(*args, **kwargs)

# ----------------------------------------------------- IssuingCas -----------------------------------------------------


class IssuingCasContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'


class IssuingCasRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:issuing_cas'


class IssuingCaListView(IssuingCasContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Issuing CAs List View."""

    model = IssuingCa
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'


class IssuingCaDetailView(IssuingCasContextMixin, TpLoginRequiredMixin, DetailView):
    """Detail view for Issuing CAs."""

    model = IssuingCa
    pk_url_kwarg = 'pk'
    template_name = 'pki/issuing_cas/details.html'

    def get_context_data(self: IssuingCaDetailView, **kwargs: Any) -> dict:
        """Adds the certificates and unique_name to the context.

        Args:
            **kwargs (Any): Keyword arguments. These are passed to super().get_context_data(**kwargs).

        Returns:
            dict:
                The context to be used for the view.
        """
        context = super().get_context_data(**kwargs)

        with default_storage.open(self.get_object().p12.name, 'rb') as f:
            certs_json = CredentialUploadHandler.parse_and_normalize_p12(f.read()).full_cert_chain_as_dict()

        context['certs'] = certs_json
        context['unique_name'] = self.get_object().unique_name
        return context


class IssuingCaLocalFileMultiForms(IssuingCasContextMixin, TpLoginRequiredMixin, MultiFormView):
    """Upload view for issuing CAs as PKCS#12 or PEM files."""

    template_name = 'pki/issuing_cas/add/local_file.html'
    forms: dict

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the IssuingCaLocalFileMulti class and add the required forms."""
        self.forms = {
            ''
            'p12_file_form': Form(
                form_name='p12_file_form',
                form_class=IssuingCaLocalP12FileForm,
                success_url=reverse_lazy('pki:issuing_cas'),
            ),
            'pem_file_form': Form(
                form_name='pem_file_form',
                form_class=IssuingCaLocalPemFileForm,
                success_url=reverse_lazy('pki:issuing_cas'),
            ),
        }
        super().__init__(*args, **kwargs)

    @staticmethod
    def _form_valid(form: IssuingCaUploadForm, request: HttpRequest, config_type: IssuingCa.ConfigType) -> None:
        """Gets the normalized P12 object from the form and saves it to the database.

        Args:
            form (IssuingCaUploadForm):
                A form that provides a normalized P12 after cleaning the form.
            request (HttpRequest):
                Django's HttpRequest object.
            config_type (IssuingCa.ConfigType):
                Enum that specifies the type of the uploaded files.

        Returns:
            None
        """
        unique_name = form.cleaned_data.get('unique_name')
        normalized_p12 = form.normalized_p12

        # noinspection DuplicatedCode
        p12_bytes_io = io.BytesIO(normalized_p12.public_bytes)
        p12_memory_uploaded_file = InMemoryUploadedFile(
            p12_bytes_io, 'p12', f'{unique_name}.p12', 'application/x-pkcs12', sys.getsizeof(p12_bytes_io), None
        )

        issuing_ca = IssuingCa(
            unique_name=unique_name,
            common_name=normalized_p12.common_name,
            #root_common_name=normalized_p12.root_common_name,
            not_valid_before=normalized_p12.not_valid_before,
            not_valid_after=normalized_p12.not_valid_after,
            key_type=normalized_p12.key_type,
            key_size=normalized_p12.key_size,
            curve=normalized_p12.curve,
            localization=normalized_p12.localization,
            config_type=str(config_type.label),
            p12=p12_memory_uploaded_file,
        )

        issuing_ca.save()

        msg = f'Success! Issuing CA - {unique_name} - is now available.'
        messages.add_message(request, messages.SUCCESS, msg)

    @classmethod
    def form_valid_p12_file_form(
        cls: type(IssuingCaLocalFileMultiForms), form: IssuingCaUploadForm, request: HttpRequest
    ) -> None:
        """Called if the p12_file_form is valid and thus saves the upload in the database.

        Args:
            form (IssuingCaUploadForm):
                A form that provides a normalized P12 after cleaning the form.
            request (HttpRequest):
                Django's HttpRequest object.

        Returns:
            None
        """
        cls._form_valid(form, request, IssuingCa.ConfigType.F_P12)

    @classmethod
    def form_valid_pem_file_form(
        cls: type(IssuingCaUploadForm), form: IssuingCaUploadForm, request: HttpRequest
    ) -> None:
        """Called if the pem_file_form is valid and thus saves the upload in the database.

        Args:
            form (IssuingCaUploadForm):
                A form that provides a normalized P12 after cleaning the form.
            request (HttpRequest):
                Django's HttpRequest object.

        Returns:
            None
        """
        cls._form_valid(form, request, IssuingCa.ConfigType.F_PEM)


class IssuingCaBulkDeleteView(
    IssuingCasContextMixin,
    MultipleObjectTemplateResponseMixin,
    BulkDeletionMixin,
    FormMixin,
    TpLoginRequiredMixin,
    BaseListView,
):
    """View that allows bulk deletion of Issuing CAs.

    This view expects a path variable pks containing string with all primary keys separated by forward slashes /.
    It cannot start with a forward slash, however a trailing forward slash is optional.
    If one or more primary keys do not have a corresponding object in the database, the user will be redirected
    to the ignore_url.
    """

    model = IssuingCa
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'objects'

    def get_ignore_url(self: IssuingCaBulkDeleteView) -> str:
        """Gets the get the configured ignore_url.

        If no ignore_url is configured, it will return the success_url.

        Returns:
            str:
                The ignore_url or success_url.

        """
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    def get_pks(self: IssuingCaBulkDeleteView) -> list[str]:
        """Gets the primary keys for the objects to delete.

        Expects a string containing the primary keys delimited by forward slashes.
        Cannot start with a forward slash.
        A trailing forward slash is optional.

        Returns:
            list[str]:
                A list of the primary keys as strings.
        """
        return self.kwargs['pks'].split('/')

    def get_queryset(self: IssuingCaBulkDeleteView, *args: Any, **kwargs: Any) -> QuerySet | None:  # noqa: ARG002
        """Gets the queryset of the objects to be deleted.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            QuerySet | None:
                The queryset of the objects to be deleted.
                None, if one or more primary keys do not have corresponding objects in the database or
                if the primary key list pks is empty.
        """
        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset

    def get(self: IssuingCaBulkDeleteView, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles HTTP GET requests.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            HttpResponse:
                The response corresponding to the HTTP GET request.
        """
        if self.get_queryset() is None:
            return redirect(self.get_ignore_url())

        return super().get(*args, **kwargs)

class AddIssuingCaLocalPki(IssuingCasContextMixin, TpLoginRequiredMixin, TemplateView):
    """Add Issuing CA Local PKI View."""

    template_name = 'pki/issuing_cas/add/local_pki.html'

class AddIssuingCaLocalRequestTemplateView(IssuingCasContextMixin, TpLoginRequiredMixin, TemplateView):
    """Add Issuing CA Local Request Template View."""

    template_name = 'pki/issuing_cas/add/local_request.html'


class AddIssuingCaRemoteEstTemplateView(IssuingCasContextMixin, TpLoginRequiredMixin, TemplateView):
    """Add Issuing CA Remote EST Template View."""

    template_name = 'pki/issuing_cas/add/remote_est.html'


class AddIssuingCaRemoteCmpTemplateView(IssuingCasContextMixin, TpLoginRequiredMixin, TemplateView):
    """Add Issuing CA Remote CMP Template View."""

    template_name = 'pki/issuing_cas/add/remote_cmp.html'
