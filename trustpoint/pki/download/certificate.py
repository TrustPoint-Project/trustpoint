from __future__ import annotations

import enum
from django.http import HttpResponse, Http404
from docutils.nodes import field

from pki.models import CertificateModel
from pki.serialization.serializer import CertificateSerializer, CertificateCollectionSerializer

class CertificateFileFormat(enum.Enum):

    PEM: str = ('pem', 'application/x-pem-file', '.pem')
    DER: str = ('der', 'application/pkix-cert', '.cer')
    PKCS7_PEM: str = ('pkcs7-pem', 'application/x-pkcs7-certificates', '.p7b')
    PKCS7_DER: str = ('pkcs7-der', 'application/x-pkcs7-certificates', '.p7b')

    def __new__(cls, value: str, mime_type: str, file_extension: str) -> CertificateFileFormat:
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class CertificateCollectionFileFormat(enum.Enum):

    PEM: str = 'pem'
    PKCS7_PEM: str = 'pkcs7_pem'
    PKCS7_DER: str = 'pkcs7_der'


class CertificateDownloadResponseBuilder:
    _django_http_response: HttpResponse | Http404

    def __init__(self, pk: int, file_format: str) -> None:
        try:
            print('aa')
            file_format = CertificateFileFormat(file_format)
            print('')
        except ValueError:
            self._set_http_404_response()
            return

        try:
            certificate_model = CertificateModel.objects.get(pk=pk)
        except CertificateModel.DoesNotExist:
            self._set_http_404_response()
            return

        certificate_serializer = certificate_model.get_certificate_serializer()

        if file_format == CertificateFileFormat.PEM:
            data = certificate_serializer.as_pem()
        elif file_format == CertificateFileFormat.DER:
            data = certificate_serializer.as_der()
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            data = certificate_serializer.as_pkcs7_pem()
        elif file_format == CertificateFileFormat.PKCS7_DER:
            data = certificate_serializer.as_pkcs7_der()
        else:
            self._set_http_404_response()
            return

        self._set_django_http_response(data, content_type=file_format.mime_type, filename='certificate' + file_format.file_extension)


    def _set_django_http_response(self, data: bytes, content_type: str, filename: str) -> None:
        self._django_http_response = HttpResponse(data, content_type=content_type)
        self._django_http_response['Content-Disposition'] = f'attachment; filename="{filename}"'

    def _set_http_404_response(self) -> None:
        self._django_response = Http404()

    def as_django_http_response(self) -> HttpResponse:
        return self._django_http_response
