from __future__ import annotations

import enum
from django.http import HttpResponse, Http404
from docutils.nodes import field

from pki.models import CertificateModel
from pki.serialization.serializer import CertificateSerializer, CertificateCollectionSerializer

class CertificateFileFormat(enum.Enum):

    PEM: str = ('pem', 'application/x-pem-file', '.pem')
    DER: str = ('der', 'application/pkix-cert', '.cer')
    PKCS7_PEM: str = ('pkcs7_pem', 'application/x-pkcs7-certificates', '.p7b')
    PKCS7_DER: str = ('pkcs7_der', 'application/x-pkcs7-certificates', '.p7b')

    def __new__(cls, value: str, mime_type: str, file_extension: str) -> CertificateFileFormat:
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class CertificateFileContent(enum.Enum):

    CERT_ONLY: str = 'cert_only'
    CERT_AND_CHAIN: str = 'cert_and_chain'
    CHAIN_ONLY: str = 'chain_only'


class CertificateDownloadResponseBuilder:
    _django_http_response: HttpResponse

    def __init__(self, pk: int, file_format: str, file_content: str) -> None:
        print(f'PK: {pk}')
        print(f'FORMAT: {file_format}')
        print(f'CONTENT: {file_content}')
        try:
            file_format = CertificateFileFormat(file_format)
        except ValueError:
            raise Http404

        try:
            file_content = CertificateFileContent(file_content)
        except ValueError:
            raise Http404

        try:
            certificate_model = CertificateModel.objects.get(pk=pk)
        except CertificateModel.DoesNotExist:
            raise Http404

        if file_content == CertificateFileContent.CERT_ONLY:
            certificate_serializer = certificate_model.get_certificate_serializer()
        elif file_content == CertificateFileContent.CERT_AND_CHAIN:
            certificate_serializer = certificate_model.get_certificate_chain_serializers(include_self=False)[0]
        elif file_content == CertificateFileContent.CHAIN_ONLY:
            certificate_serializer = certificate_model.get_certificate_chain_serializers()[0]
        else:
            raise Http404

        if file_format == CertificateFileFormat.PEM:
            data = certificate_serializer.as_pem()
        elif file_content == CertificateFileContent.CERT_ONLY and file_format == CertificateFileFormat.DER:
            data = certificate_serializer.as_der()
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            data = certificate_serializer.as_pkcs7_pem()
        elif file_format == CertificateFileFormat.PKCS7_DER:
            data = certificate_serializer.as_pkcs7_der()
        else:
            raise Http404

        self._set_django_http_response(data, content_type=file_format.mime_type, filename='certificate' + file_format.file_extension)


    def _set_django_http_response(self, data: bytes, content_type: str, filename: str) -> None:
        self._django_http_response = HttpResponse(data, content_type=content_type)
        self._django_http_response['Content-Disposition'] = f'attachment; filename="{filename}"'

    def as_django_http_response(self) -> HttpResponse:
        return self._django_http_response

