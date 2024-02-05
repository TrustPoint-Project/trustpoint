import sys
import io
from util.x509.credentials import CredentialUploadHandler

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import render, redirect
from django.forms.utils import ErrorList

from .forms import IssuingCaLocalP12FileForm, IssuingCaLocalPemFileForm
from .models import LocalIssuingCa, IssuingCa


def pki(request):
    return redirect('pki-endpoint-profiles')


# Create your views here.
def endpoint_profiles(request):
    context = {
        'page_category': 'pki',
        'page_name': 'endpoint_profiles'
    }
    return render(request, 'pki/endpoint_profiles.html', context=context)


def certificate_authorities(request):
    context = {
        'page_category': 'pki',
        'page_name': 'certificate_authorities'
    }
    return render(request, 'pki/certificate_authorities.html', context=context)


def add_ca_local_file(request):
    context = {
        'page_category': 'pki',
        'page_name': 'certificate_authorities',
    }

    # TODO: create decorator for unexpected exception handling
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
                        'Failed to parse P12 file. Invalid password or PKCS#12 data.')
                    p12_file_form.errors.setdefault('p12_password', ErrorList()).append(
                        'Failed to parse P12 file. Invalid password or PKCS#12 data.')
                    context['p12_file_form'] = p12_file_form
                    context['pem_file_form'] = IssuingCaLocalPemFileForm()
                    return render(request, 'pki/certificate_authorities/add/local_file.html', context=context)

                unique_name = p12_file_form.cleaned_data.get('unique_name')
                if IssuingCa.objects.filter(unique_name=unique_name).exists():
                    p12_file_form.errors.setdefault('unique_name', ErrorList()).append(
                        'Unique name is already taken. Try another one.')
                    context['p12_file_form'] = p12_file_form
                    context['pem_file_form'] = IssuingCaLocalPemFileForm()
                    return render(request, 'pki/certificate_authorities/add/local_file.html', context=context)

                p12_bytes_io = io.BytesIO(normalized_p12.public_bytes)
                p12_memory_uploaded_file = InMemoryUploadedFile(
                    p12_bytes_io,
                    'p12',
                    f'{unique_name}.p12',
                    'application/x-pkcs12',
                    sys.getsizeof(p12_bytes_io),
                    None
                )

                local_issuing_ca = LocalIssuingCa(p12=p12_memory_uploaded_file)
                issuing_ca = IssuingCa(
                    unique_name=unique_name,
                    subject=normalized_p12.subject,
                    issuer=normalized_p12.issuer,
                    not_valid_before=normalized_p12.not_valid_before,
                    not_valid_after=normalized_p12.not_valid_after,
                    root_subject=normalized_p12.root_subject,
                    chain_not_valid_before=normalized_p12.chain_not_valid_before,
                    chain_not_valid_after=normalized_p12.chain_not_valid_after,
                    key_type=normalized_p12.key_type,
                    key_size=normalized_p12.key_size,
                    curve=normalized_p12.curve,
                    local_issuing_ca=local_issuing_ca)

                # TODO: check if this is kind of atomic or could result in issues
                local_issuing_ca.save()
                issuing_ca.save()

            # else:
                context['p12_file_form'] = p12_file_form
                context['pem_file_form'] = IssuingCaLocalPemFileForm()
                return render(request, 'pki/certificate_authorities/add/local_file.html', context=context)

    # else:

    context['p12_file_form'] = IssuingCaLocalP12FileForm()
    context['pem_file_form'] = IssuingCaLocalPemFileForm()

    return render(request, 'pki/certificate_authorities/add/local_file.html', context=context)


def add_ca_local_request(request):
    context = {
        'page_category': 'pki',
        'page_name': 'certificate_authorities'
    }
    return render(request, 'pki/certificate_authorities/add/local_request.html', context=context)


def add_ca_remote_est(request):
    context = {
        'page_category': 'pki',
        'page_name': 'certificate_authorities'
    }
    return render(request, 'pki/certificate_authorities/add/remote_est.html', context=context)


def add_ca_remote_cmp(request):
    context = {
        'page_category': 'pki',
        'page_name': 'certificate_authorities'
    }
    return render(request, 'pki/certificate_authorities/add/remote_cmp.html', context=context)
