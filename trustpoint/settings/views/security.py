"""Django Views"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.edit import FormView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from util.keys import SignatureSuite

from settings.forms import SecurityConfigForm
from settings.models import SecurityConfig
from settings.security import manager
from settings.security.features import AutoGenPkiFeature, SecurityFeature
from settings.security.manager import SecurityManager
from settings.security.mixins import SecurityLevelMixin
from trustpoint.views.base import (
    TpLoginRequiredMixin,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse



class SecurityView(TpLoginRequiredMixin, SecurityLevelMixin, FormView):
    template_name = 'settings/security.html'
    form_class = SecurityConfigForm
    success_url = reverse_lazy('settings:security')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        try:
            security_config = SecurityConfig.objects.get(id=1)
        except ObjectDoesNotExist:
            security_config = SecurityConfig()
        kwargs['instance'] = security_config
        return kwargs

    def form_valid(self, form: SecurityConfigForm):
        old_conf = SecurityConfig.objects.get(pk=form.instance.pk) if form.instance.pk else None
        form.save()

        if 'security_mode' in form.changed_data:
            old_value = getattr(old_conf, 'security_mode', None) if old_conf else None
            new_value = form.cleaned_data.get('security_mode', None)

            # Safely convert to int for comparison (default to 0 if None)
            old_int = int(old_value) if old_value else 0
            new_int = int(new_value)

            if new_int > old_int:
                self.sec.reset_settings(new_value)

        if 'auto_gen_pki' in form.changed_data:
            old_auto = getattr(old_conf, 'auto_gen_pki', None) if old_conf else None
            new_auto = form.cleaned_data.get('auto_gen_pki', None)

            if old_auto != new_auto and new_auto:
                # autogen PKI got enabled
                key_alg = SignatureSuite(form.cleaned_data.get('auto_gen_pki_key_algorithm'))
                self.sec.enable_feature(AutoGenPkiFeature, key_alg)

            elif old_auto != new_auto and not new_auto:
                # autogen PKI got disabled
                print('I WANT TO BREAK FREE')
                AutoGenPkiFeature.disable()

        messages.success(self.request, _('Your changes were saved successfully.'))
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, _('Error saving the configuration'))
        return self.render_to_response(self.get_context_data(form=form))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'settings'
        context['page_name'] = 'security'
        return context
