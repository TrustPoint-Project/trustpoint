"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404) as well as specific mixins and view classes
which can be used within the apps.
"""

from __future__ import annotations

from typing import Any, Callable

from django import forms as dj_forms
from django.contrib import messages
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView
from django.views.generic.edit import FormMixin
from django.views.generic.list import BaseListView, MultipleObjectTemplateResponseMixin


from django.db.models import Model

from django.views.generic import ListView
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from django.db.models import QuerySet, Model


class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent: bool = False
    pattern_name: str = 'home:dashboard'


class TpLoginRequiredMixin(LoginRequiredMixin):
    """LoginRequiredMixin that adds a warning message if the user is not logged in."""
    request: HttpRequest

    def handle_no_permission(self) -> str:
        """Redirects to the login page with a warning message if the user is not logged in."""
        messages.add_message(self.request, messages.WARNING, message=_('Login required!'))
        return super().handle_no_permission()


class ContextDataMixin:
    def get_context_data(self, **kwargs: Any) -> dict:
        """Adds attributes prefixed with context_ to the context_data if it does not exist.

        Note:
            If another succeeding class in the MRO has another get_context_data method,
            this method will be called after setting the attributes to the context_data.

        Example:
            Lets consider context_page_category.
            Then the attribute page_category with the value of context_page_category is
            added to the context_data if page_category does not already exist in the context_data.

        Example:
            The following Mixin will add 'page_category': 'pki', and 'page_name': 'endpoint_profiles'
             to the context data.

            class EndpointProfilesExtraContextMixin(ContextDataMixin):
                \"\"\"Mixin which adds context_data for the PKI -> Endpoint Profiles pages.\"\"\"

                context_page_category = 'pki'
                context_page_name = 'endpoint_profiles'
        """
        prefix = 'context_'
        for attr in dir(self):
            if attr.startswith(prefix) and len(attr) > len(prefix):
                kwargs.setdefault(attr[len(prefix):], getattr(self, attr))

        super_get_context_method = getattr(super(), 'get_context_data', None)
        if super_get_context_method is None:
            return kwargs
        else:
            return super_get_context_method(**kwargs)


class BulkDeletionMixin:

    queryset: Any
    get_queryset: Callable
    success_url = None
    object_list = list

    def delete(self, *args, **kwargs):
        self.queryset = self.get_queryset()
        success_url = self.get_success_url()
        self.queryset.delete()
        return HttpResponseRedirect(success_url)

    def post(self, request, *args, **kwargs):
        return self.delete(request, *args, **kwargs)

    def get_success_url(self):
        if self.success_url:
            return self.success_url

        raise ImproperlyConfigured("No URL to redirect to. Provide a success_url.")


class BaseBulkDeleteView(BulkDeletionMixin, FormMixin, BaseListView):

    form_class = dj_forms.Form

    def post(self, *args, **kwargs):
        self.queryset = self.get_queryset()
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, form):
        success_url = self.get_success_url()
        self.queryset.delete()
        return HttpResponseRedirect(success_url)


class PrimaryKeyFromUrlToQuerysetMixin:

    kwargs: dict
    queryset: QuerySet
    model: Model

    def get_pks(self) -> list[str]:
        return self.kwargs['pks'].split('/')

    def get_queryset(self) -> QuerySet | None:
        if self.queryset:
            return self.queryset

        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset


class BulkDeleteView(MultipleObjectTemplateResponseMixin, PrimaryKeyFromUrlToQuerysetMixin, BaseBulkDeleteView):
    pass
