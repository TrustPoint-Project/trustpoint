"""Django Views"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views.generic.base import RedirectView

import os
from pathlib import Path
import datetime
import io
import re
import zipfile
import tarfile

from django.http import Http404, HttpResponse
from django.views.generic import TemplateView, View
from django_tables2 import SingleTableView

from trustpoint.settings import LOG_DIR_PATH, DATE_FORMAT

from .tables import LogFileTable
from trustpoint.views.base import TpLoginRequiredMixin, LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse
    from typing import Any


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
    @LoggerMixin.log_exceptions
    def _get_first_and_last_entry_date(
            log_file_path: Path
    ) -> tuple[None | datetime.datetime, None | datetime.datetime]:
        log_file = log_file_path.read_text()

        date_regex = re.compile(r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b')
        matches = re.findall(date_regex, log_file)
        if matches:
            first_date = datetime.datetime.strptime(matches[0], DATE_FORMAT)
            last_date = datetime.datetime.strptime(matches[-1], DATE_FORMAT)
        else:
            first_date = None
            last_date = None

        return first_date, last_date

    @classmethod
    @LoggerMixin.log_exceptions
    def _get_log_file_data(cls, log_filename: str) -> dict[str, str]:
        log_file_path = LOG_DIR_PATH / Path(log_filename)
        if not log_file_path.exists() or not log_file_path.is_file():
            return {}

        first_date, last_date = cls._get_first_and_last_entry_date(log_file_path)
        if isinstance(first_date, datetime.datetime):
            created_at = first_date.strftime(f'{DATE_FORMAT} UTC')
        else:
            created_at = _('None')

        if isinstance(last_date, datetime.datetime):
            updated_at = last_date.strftime(f'{DATE_FORMAT} UTC')
        else:
            updated_at = _('None')


        return {
            'filename': log_filename,
            'created_at': created_at,
            'updated_at': updated_at
        }

    @LoggerMixin.log_exceptions
    def get_queryset(self) -> list[dict[str, str]]:
        return [self._get_log_file_data(log_file_name) for log_file_name in os.listdir(LOG_DIR_PATH)]


class LoggingFilesDetailsView(LoggerMixin, LoggingContextMixin, TpLoginRequiredMixin, TemplateView):
    http_method_names = ['get']

    template_name = 'settings/logging/logging_files_details.html'
    log_directory = LOG_DIR_PATH

    @LoggerMixin.log_exceptions
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

    @LoggerMixin.log_exceptions
    def get(self, *args, **kwargs):
        filename = kwargs.get('filename')
        log_file_path = LOG_DIR_PATH / Path(filename)

        if not log_file_path.exists() or not log_file_path.is_file():
            raise Http404('Log-File not found.')

        response = HttpResponse(log_file_path.read_text(), content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename={filename}'
        return response


class LoggingFilesDownloadMultipleView(LoggerMixin, LoggingContextMixin, TpLoginRequiredMixin, View):
    http_method_names = ['get']

    @classmethod
    @LoggerMixin.log_exceptions
    def get(cls, *args, **kwargs) -> HttpResponse:
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
