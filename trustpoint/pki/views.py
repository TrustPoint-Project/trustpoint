import sys
import io
from util.x509.credentials import CredentialUploadHandler

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import render, redirect
from django.forms.utils import ErrorList
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin

from django_tables2 import SingleTableView

from .forms import IssuingCaLocalP12FileForm, IssuingCaLocalPemFileForm
from .models import LocalIssuingCa, IssuingCa
from .tables import IssuingCaTable

from django.urls import reverse_lazy
from django.views.generic.edit import DeleteView
from django.views.generic.detail import DetailView
from django.core.files.storage import default_storage
from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    permanent = True
    pattern_name = 'pki:endpoint_profiles'


# Create your views here.
def endpoint_profiles(request):
    context = {'page_category': 'pki', 'page_name': 'endpoint_profiles'}
    return render(request, 'pki/endpoint_profiles.html', context=context)


class IssuingCaDeleteView(SuccessMessageMixin, DeleteView):
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


class IssuingCaDetailView(DetailView):
    model = IssuingCa


class IssuingCaListView(SingleTableView):
    model = IssuingCa
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'pki'
        context['page_name'] = 'issuing_cas'
        return context


def issuing_ca_detail(request, pk):
    object_ = IssuingCa.objects.filter(pk=pk).first()
    if not object_:
        return redirect('pki:issuing_cas')

    with default_storage.open(object_.local_issuing_ca.p12.name, 'rb') as f:
        certs_json = CredentialUploadHandler.parse_and_normalize_p12(f.read()).full_cert_chain_as_json()

    context = {
        'page_category': 'pki',
        'page_name': 'issuing_cas',
        'unique_name': object_.unique_name,
        'certs': certs_json,
    }

    return render(request, 'pki/issuing_cas/details.html', context=context)


# TODO: create decorator for unexpected exception handling
def add_issuing_ca_local_file(request):
    context = {
        'page_category': 'pki',
        'page_name': 'issuing_cas',
    }

    if request.method == 'POST':
        if 'p12-file-form' in request.POST:
            p12_file_form = IssuingCaLocalP12FileForm(request.POST, request.FILES)

            if p12_file_form.is_valid():
                p12 = request.FILES.get('p12').read()
                p12_password = p12_file_form.cleaned_data.get('p12_password').encode()

                # noinspection PyBroadException
                try:
                    normalized_p12 = CredentialUploadHandler.parse_and_normalize_p12(p12, p12_password)
                except Exception:
                    p12_file_form.errors.setdefault('p12', ErrorList()).append(
                        'Failed to parse P12 file. Invalid password or PKCS#12 data.'
                    )
                    p12_file_form.errors.setdefault('p12_password', ErrorList()).append(
                        'Failed to parse P12 file. Invalid password or PKCS#12 data.'
                    )
                    context['p12_file_form'] = p12_file_form
                    context['pem_file_form'] = IssuingCaLocalPemFileForm()
                    return render(request, 'pki/issuing_cas/add/local_file.html', context=context)

                unique_name = p12_file_form.cleaned_data.get('unique_name')
                if IssuingCa.objects.filter(unique_name=unique_name).exists():
                    p12_file_form.errors.setdefault('unique_name', ErrorList()).append(
                        'Unique name is already taken. Try another one.'
                    )
                    context['p12_file_form'] = p12_file_form
                    context['pem_file_form'] = IssuingCaLocalPemFileForm()
                    return render(request, 'pki/issuing_cas/add/local_file.html', context=context)

                p12_bytes_io = io.BytesIO(normalized_p12.public_bytes)
                p12_memory_uploaded_file = InMemoryUploadedFile(
                    p12_bytes_io, 'p12', f'{unique_name}.p12', 'application/x-pkcs12', sys.getsizeof(p12_bytes_io), None
                )

                local_issuing_ca = LocalIssuingCa(p12=p12_memory_uploaded_file)
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
                    local_issuing_ca=local_issuing_ca,
                )

                # TODO: check if this is kind of atomic or could result in issues
                local_issuing_ca.save()
                issuing_ca.save()

                msg = f'Success! Issuing CA - {unique_name} - is now available.'
                messages.add_message(request, messages.SUCCESS, msg)

                return redirect('pki:issuing_cas')

            # TODO: PEM import
            # TODO: Error handling

    context['p12_file_form'] = IssuingCaLocalP12FileForm()
    context['pem_file_form'] = IssuingCaLocalPemFileForm()

    return render(request, 'pki/issuing_cas/add/local_file.html', context=context)


def add_issuing_ca_local_request(request):
    context = {'page_category': 'pki', 'page_name': 'issuing_cas'}
    return render(request, 'pki/issuing_cas/add/local_request.html', context=context)


def add_issuing_ca_remote_est(request):
    context = {'page_category': 'pki', 'page_name': 'issuing_cas'}
    return render(request, 'pki/issuing_cas/add/remote_est.html', context=context)


def add_issuing_ca_remote_cmp(request):
    context = {'page_category': 'pki', 'page_name': 'issuing_cas'}
    return render(request, 'pki/issuing_cas/add/remote_cmp.html', context=context)
