from django.shortcuts import render, redirect
from django.views.generic import CreateView
from .models import IssuingCa
from django.urls import reverse_lazy
from .forms import IssuingCaP12Form, IssuingCaPemForm, IssuingCaLocalP12FileForm, IssuingCaLocalPemFileForm


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
        'issuing_ca_p12_form': IssuingCaP12Form(auto_id='p12_%s'),
        'issuing_ca_pem_form': IssuingCaPemForm(auto_id='pem_%s'),
        'p12_file_form': IssuingCaLocalP12FileForm(),
        'pem_file_form': IssuingCaLocalPemFileForm()
    }

    if request.method == 'POST':
        issuing_ca_form = IssuingCaP12Form(request.POST)
        p12_file_form = IssuingCaLocalP12FileForm(request.POST, request.FILES)
        if issuing_ca_form.is_valid() and p12_file_form.is_valid():
            # file = p12_file_form.save(commit=False)
            # issuing_ca = issuing_ca_form.save(commit=False)
            # issuing_ca.local_issuing_ca = file
            # file.save()
            # issuing_ca.save()
            return redirect('pki-ca')
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
