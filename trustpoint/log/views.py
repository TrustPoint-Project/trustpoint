"""Views for the log application."""

import os
import time
import zipfile
from io import BytesIO

from django.conf import settings
from django.contrib import messages
from django.http import Http404, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import TemplateView, View
from django_tables2 import SingleTableView

from .tables import LogFileTable


class LogTableView(SingleTableView):
    template_name = 'log.html'
    table_class = LogFileTable

    def get_queryset(self):
        log_directory = os.path.join(settings.MEDIA_ROOT, 'log')
        logs = []
        for log_filename in os.listdir(log_directory):
            log_path = os.path.join(log_directory, log_filename)
            if os.path.isfile(log_path):
                log_date = time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(log_path)))
                logs.append({'filename': log_filename, 'date': log_date})
        return logs


class LogDetailView(TemplateView):
    template_name = 'log_detail.html'
    log_directory = os.path.join(settings.MEDIA_ROOT, 'log')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        log_filename = self.kwargs.get('filename')
        log_path = os.path.join(self.log_directory, log_filename)

        try:
            with open(log_path, 'r') as log_file:
                log_content = log_file.read()
        except FileNotFoundError:
            log_content = "File not found."

        context['log_content'] = log_content
        return context


class LogDownloadView(TemplateView):
    """View to download a single log file"""
    def get(self, request, filename):
        log_dir = 'media/log'
        log_path = os.path.join(log_dir, filename)

        if not os.path.exists(log_path):
            raise Http404("Log file not found")

        with open(log_path, 'rb') as log_file:
            response = HttpResponse(log_file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={filename}.txt'
            return response


class LogDownloadZipView(View):

    redirection_view = reverse_lazy('log:logs')

    def post(self, request, *args, **kwargs):
        selected_files = request.POST.getlist('row_checkbox')

        if not selected_files:
            messages.error(request, "No files selected.")
            return redirect(self.redirection_view)

        zip_filename = "logs.zip"
        zip_path = os.path.join(settings.MEDIA_ROOT, zip_filename)

        with zipfile.ZipFile(zip_path, 'w') as log_zip:
            for log_filename in selected_files:
                log_path = os.path.join(settings.MEDIA_ROOT, 'log', log_filename)
                if os.path.exists(log_path):
                    log_zip.write(log_path, os.path.basename(log_path) + '.txt')
                else:
                    messages.error(request, f"Log file {log_filename} not found")
                    return redirect(self.redirection_view)

        with open(zip_path, 'rb') as zip_file:
            response = HttpResponse(zip_file.read(), content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename={zip_filename}'
            return response
