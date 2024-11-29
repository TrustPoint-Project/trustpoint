"""Django Views"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView

import os
from pathlib import Path
import datetime
import io
import zipfile
import tarfile

from django.contrib import messages
from django.http import Http404, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView, View
from django_tables2 import SingleTableView

from trustpoint.settings import LOG_DIR_PATH, DATE_FORMAT

from .tables import LogFileTable
from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin, LoggerMixin

from .forms import SecurityConfigForm
from .models import SecurityConfig
from .security.manager import SecurityFeatures, SecurityManager

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse
    from typing import Any


class SecurityLevelMixin:
    """A mixin that provides security feature checks for Django views."""

    def __init__(self, security_feature: None | SecurityFeatures = None, *args, **kwargs) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Parameters:
        -----------
        security_feature : SecurityFeatures, optional
            The feature to check against the current security level (default is None).
        *args, **kwargs:
            Additional arguments passed to the superclass initializer.
        """
        super().__init__(*args, **kwargs)
        self.sec = SecurityManager()
        self.security_feature = security_feature

    def get_security_level(self):
        """Returns the security mode of the current security level instance.

        Returns:
        --------
        str
            The security mode of the current security level instance.
        """
        return self.sec.get_security_level()


class SecurityLevelMixinRedirect(SecurityLevelMixin):
    """A mixin that provides security feature checks for Django views with redirect feature."""

    def __init__(self, disabled_by_security_level_url=None, *args, **kwargs) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Parameters:
        -----------
        security_feature : SecurityFeatures, optional
            The feature to check against the current security level (default is None).
        *args, **kwargs:
            Additional arguments passed to the superclass initializer.
        """
        super().__init__(*args, **kwargs)
        self.disabled_by_security_level_url = disabled_by_security_level_url

    def dispatch(self, request, *args, **kwargs):
        """If the feature is not allowed, the user is redirected to the disabled_by_security_level_url with an error message.

        Parameters:
        -----------
        request : HttpRequest
            The HTTP request object.
        *args, **kwargs:
            Additional arguments passed to the dispatch method.

        Returns:
        --------
        HttpResponse or HttpResponseRedirect
            The HTTP response object, either continuing to the requested view or redirecting.
        """
        if not self.sec.is_feature_allowed(self.security_feature):
            msg = _('Your security setting %s does not allow the feature: %s' % (self.get_security_level(), self.security_feature.value))
            messages.error(request, msg)
            return redirect(self.disabled_by_security_level_url)
        return super().dispatch(request, *args, **kwargs)


class IndexView(RedirectView):
    """Index view"""
    permanent = True
    pattern_name = 'settings:language'


def language(request: HttpRequest) -> HttpResponse:
    """Handle language Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'settings', 'page_name': 'language'}
    return render(request, 'settings/language.html', context=context)


@login_required
def security(request: HttpRequest) -> HttpResponse:
    """Handle Security Configuration

    Returns: HTTPResponse
    """
    context = {'page_category': 'settings', 'page_name': 'security'}

    # Try to read the configuration
    try:
        security_config = SecurityConfig.objects.get(id=1)
    except ObjectDoesNotExist:
        # create an empty configuration
        security_config = SecurityConfig()

    if request.method == 'POST':
        security_configuration_form = SecurityConfigForm(request.POST, instance=security_config)
        if security_configuration_form.is_valid():
            security_configuration_form.save()
            messages.success(request, _('Your changes were saved successfully.'))
            # use a new form instance to apply new original values
            context['security_config_form'] = SecurityConfigForm(instance=security_config)
            return render(request, 'settings/security.html', context=context)

        messages.error(request, _('Error saving the configuration'))
        context['security_config_form'] = security_configuration_form
        return render(request, 'settings/security.html', context=context)

    context['security_config_form'] = SecurityConfigForm(instance=security_config)
    return render(request, 'settings/security.html', context=context)


# ------------------------------------------------------- Logging ------------------------------------------------------


class LoggingContextMixin:
    """Mixin which adds some extra context for the Logging Views."""

    extra_context = {
        'page_category': 'settings',
        'page_name': 'logging'
    }


class LoggingFilesTableView(LoggerMixin, TpLoginRequiredMixin, LoggingContextMixin, SingleTableView):
    http_method_names = ['get']

    template_name = 'settings/logging/logging_files.html'
    table_class = LogFileTable

    @staticmethod
    def _get_first_and_last_entry_date(log_file_path: Path) -> tuple[datetime.datetime, datetime.datetime]:
        with log_file_path.open('r') as file:
            first_line = file.readline().strip()
            if first_line:
                try:

                    first_date = datetime.datetime.strptime(
                        first_line.split()[0] + " " + first_line.split()[1], DATE_FORMAT)
                except (ValueError, IndexError):
                    pass

            for line in file:
                pass

            if line.strip():
                try:
                    last_date = datetime.datetime.strptime(line.split()[0] + " " + line.split()[1], DATE_FORMAT)
                except (ValueError, IndexError):
                    pass

        return first_date, last_date

    @classmethod
    def _get_log_file_data(cls, log_filename: str) -> dict[str, str]:
        log_file_path = LOG_DIR_PATH / Path(log_filename)
        if not log_file_path.exists() or not log_file_path.is_file():
            return {}

        first_date, last_date = cls._get_first_and_last_entry_date(log_file_path)

        return {
            'filename': log_filename,
            'created_at': first_date.strftime(f'{DATE_FORMAT} UTC'),
            'updated_at': last_date.strftime(f'{DATE_FORMAT} UTC'),
        }

    def get_queryset(self) -> list[dict[str, str]]:
        return [self._get_log_file_data(log_file_name) for log_file_name in os.listdir(LOG_DIR_PATH)]


class LoggingFilesDetailsView(LoggerMixin, LoggingContextMixin, TpLoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    template_name = 'settings/logging/logging_files_details.html'
    log_directory = LOG_DIR_PATH

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        log_filename = self.kwargs.get('filename')

        log_file_path = LOG_DIR_PATH / Path(log_filename)

        if not log_file_path.exists() or not log_file_path.is_file():
            context['log_content'] = 'Log-File not found.'
        else:
            context['log_content'] = log_file_path.read_text()

        return context


class LoggingFilesDownloadView(LoggerMixin, LoggingContextMixin, TpLoginRequiredMixin, TemplateView):
    """View to download a single log file"""
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        filename = kwargs.get('filename')
        log_file_path = LOG_DIR_PATH / Path(filename)

        if not log_file_path.exists() or not log_file_path.is_file():
            raise Http404('Log-File not found.')

        response = HttpResponse(log_file_path.read_text(), content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename={filename}'
        return response


class LoggingFilesDownloadMultipleView(LoggerMixin, LoggingContextMixin, TpLoginRequiredMixin, View):
    http_method_names = ['get']

    @staticmethod
    def get(*args, **kwargs) -> HttpResponse:
        archive_format = kwargs.get('archive_format')
        filenames = kwargs.get('filenames')

        # These should never happen, due to the regex in the urls.py (re_path). ----------------------------------------
        if not archive_format or not filenames:
            raise Http404('Log-Files not found.')
        if archive_format not in ['zip', 'tar.gz']:
            raise Http404('Invalid archive format found.')
        # --------------------------------------------------------------------------------------------------------------

        filenames = [filename for filename in filenames.split('/') if filename]

        file_collection = [
            (filename, (LOG_DIR_PATH / Path(filename)).read_bytes())
            for filename in filenames
        ]

        if archive_format.lower() == 'zip':
            bytes_io = io.BytesIO()
            zip_file = zipfile.ZipFile(bytes_io, 'w')
            for filename, data in file_collection:
                zip_file.writestr(filename, data)
            zip_file.close()

            response = HttpResponse(bytes_io.getvalue(), content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename=trustpoint-logs.zip'
            return response

        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for filename, data in file_collection:
                file_io_bytes = io.BytesIO(data)
                file_io_bytes_info = tarfile.TarInfo(filename)
                file_io_bytes_info.size = len(data)
                tar.addfile(file_io_bytes_info, file_io_bytes)

        response = HttpResponse(bytes_io.getvalue(), content_type='application/gzip')
        response['Content-Disposition'] = f'attachment; filename=trustpoint-logs.tar.gz'
        return response
