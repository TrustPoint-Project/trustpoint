"""Contains some views specific to the PKI application."""


from __future__ import annotations

import io
import sys

from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.edit import DeleteView, FormView
from django_tables2 import SingleTableView
from util.x509.credentials import CredentialUploadHandler

from trustpoint.views import Form, MultiFormView, PageContextDataMixin

from .forms import IssuingCaLocalP12FileForm, IssuingCaLocalPemFileForm
from .models import IssuingCa
from .tables import IssuingCaTable


class EndpointProfilesExtraContextMixin(PageContextDataMixin):
    """Mixin which adds context_data for the PKI -> Endpoint Profiles pages."""

    page_category = 'pki'
    page_name = 'endpoint_profiles'


class IssuingCasExtraContextMixin(PageContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    page_category = 'pki'
    page_name = 'issuing_cas'


class IndexView(RedirectView):
    """View that redirects to the index of the PKI application: Endpoint Profiles."""

    permanent = True
    pattern_name = 'pki:endpoint_profiles'


class EndpointProfilesTemplateView(EndpointProfilesExtraContextMixin, TemplateView):
    """Endpoint Profiles Template View."""

    template_name = 'pki/endpoint_profiles.html'


class IssuingCaListView(IssuingCasExtraContextMixin, SingleTableView):
    """Index-view of PKI -> Issuing CAs."""

    model = IssuingCa
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'


class IssuingCaLocalFile(FormView):
    template_name = 'pki/issuing_cas/add/local_file.html'
    form_class = IssuingCaLocalP12FileForm
    success_url = reverse_lazy('pki:issuing_cas')

    def get_context_data(self, **kwargs):
        """Insert the form into the context dict."""
        if 'p12_file_form' not in kwargs:
            kwargs['p12_file_form'] = self.get_form()
        return super().get_context_data(**kwargs)


class IssuingCaLocalFileMulti(IssuingCasExtraContextMixin, MultiFormView):
    template_name = 'pki/issuing_cas/add/local_file.html'
    forms = {
        'p12_file_form': Form(
            form_name='p12_file_form', form_class=IssuingCaLocalP12FileForm, success_url=reverse_lazy('pki:issuing_cas')
        ),
        'pem_file_form': Form(
            form_name='pem_file_form', form_class=IssuingCaLocalPemFileForm, success_url=reverse_lazy('pki:issuing_cas')
        ),
    }

    @staticmethod
    def on_valid_form_p12_file_form(form, request):
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
            root_common_name=normalized_p12.root_common_name,
            not_valid_before=normalized_p12.not_valid_before,
            not_valid_after=normalized_p12.not_valid_after,
            key_type=normalized_p12.key_type,
            key_size=normalized_p12.key_size,
            curve=normalized_p12.curve,
            localization=normalized_p12.localization,
            config_type=normalized_p12.config_type,
            p12=p12_memory_uploaded_file,
        )

        # TODO(Alex): check if this is kind of atomic or could result in issues
        issuing_ca.save()

        msg = f'Success! Issuing CA - {unique_name} - is now available.'
        messages.add_message(request, messages.SUCCESS, msg)

    @staticmethod
    def on_valid_form_pem_file_form(form_name: str, form):
        # TODO(Alex)
        pass


class IssuingCaDeleteView(SuccessMessageMixin, DeleteView):
    """Issuing CA Delete View."""

    model = IssuingCa
    success_url = reverse_lazy('pki-issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'

    def get_success_message(self, cleaned_data):
        return f'Success! Issuing CA - {self.object.unique_name} - deleted successfully!.'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'pki'
        context['page_name'] = 'issuing_cas'
        return context


def bulk_delete_issuing_cas(request, issuing_cas):
    pks = issuing_cas.split('/')
    context = {
        'page_category': 'pki',
        'page_name': 'endpoint_profiles',
    }

    if request.method == 'GET':
        if len(pks) == 1:
            context['list_heading'] = 'Are you sure you want to delete this Issuing CA?'
        else:
            context['list_heading'] = 'Are you sure you want to delete these Issuing CAs?'

        objects = IssuingCa.objects.filter(pk__in=pks)
        context['objects'] = objects

        return render(request, 'pki/issuing_cas/confirm_delete.html', context=context)

    if request.method == 'POST':
        objects = IssuingCa.objects.filter(pk__in=pks)
        if len(pks) == 1:
            msg = f'Success! Issuing CA - {objects[0].unique_name} - deleted!.'
        else:
            msg = 'Success! All selected Issuing CAs deleted!.'
        objects.delete()
        messages.add_message(request, messages.SUCCESS, msg)
        return redirect('pki:issuing_cas')

    return render(request, 'pki/issuing_cas/confirm_delete.html', context=context)


def issuing_ca_detail(request, pk):
    object_ = IssuingCa.objects.filter(pk=pk).first()
    if not object_:
        return redirect('pki:issuing_cas')

    with default_storage.open(object_.p12.name, 'rb') as f:
        certs_json = CredentialUploadHandler.parse_and_normalize_p12(f.read()).full_cert_chain_as_json()

    context = {
        'page_category': 'pki',
        'page_name': 'issuing_cas',
        'unique_name': object_.unique_name,
        'certs': certs_json,
    }

    return render(request, 'pki/issuing_cas/details.html', context=context)


class AddIssuingCaLocalRequestTemplateView(IssuingCasExtraContextMixin, TemplateView):
    """Add Issuing CA Local Request Template View."""

    template_name = 'pki/issuing_cas/add/local_request.html'


class AddIssuingCaRemoteEstTemplateView(IssuingCasExtraContextMixin, TemplateView):
    """Add Issuing CA Remote EST Template View."""

    template_name = 'pki/issuing_cas/add/remote_est.html'


class AddIssuingCaRemoteCmpTemplateView(IssuingCasExtraContextMixin, TemplateView):
    """Add Issuing CA Remote CMP Template View."""

    template_name = 'pki/issuing_cas/add/remote_cmp.html'
