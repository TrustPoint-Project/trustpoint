from __future__ import annotations

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.translation import gettext as _
from django.views import View

from pki.models import BaseCaModel


class CRLDownloadView(View):
    """Revoked Certificates download view."""

    @staticmethod
    def download_ca_crl(self: CRLDownloadView, ca_id):
        try:
            issuing_ca = BaseCaModel.objects.get(pk=ca_id).get_issuing_ca()
        except BaseCaModel.DoesNotExist:
            messages.error(self, _('Issuing CA not found.'))
            return redirect('pki:issuing_cas')

        crl_data = issuing_ca.get_crl_as_str()
        if not crl_data:
            messages.warning(self, _('No CRL available for issuing CA %s.') % issuing_ca.get_ca_name())
            return redirect('pki:issuing_cas')
        response = HttpResponse(crl_data, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{issuing_ca.get_ca_name()}.crl"'
        return response

    @staticmethod
    def generate_ca_crl(self: CRLDownloadView, ca_id):
        try:
            issuing_ca = BaseCaModel.objects.get(pk=ca_id).get_issuing_ca()
        except BaseCaModel.DoesNotExist:
            messages.error(self, _('Issuing CA not found.'))
            return redirect('pki:issuing_cas')

        if issuing_ca.generate_crl():
            messages.info(self, _('CRL generated'))
        else:
            messages.warning(self, _('CRL could not be generated'))
        return redirect('pki:issuing_cas')
