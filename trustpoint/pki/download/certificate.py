from __future__ import annotations

import enum
import io
import tarfile
import zipfile

from django.http import Http404, HttpResponse


from pki.models import CertificateModel
from core import archiver


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


class CertificateArchiveFormat(enum.Enum):

    ZIP: str = 'zip'
    TAR_GZ: str = 'tar_gz'


class DownloadResponseBuilder:
    _django_http_response: HttpResponse

    def _set_django_http_response(self, data: bytes, content_type: str, filename: str) -> None:
        self._django_http_response = HttpResponse(data, content_type=content_type)
        self._django_http_response['Content-Disposition'] = f'attachment; filename="{filename}"'

    def as_django_http_response(self) -> HttpResponse:
        return self._django_http_response


class CertificateDownloadResponseBuilder(DownloadResponseBuilder):

    def __init__(self, pk: int, file_format: str, file_content: str) -> None:
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
            certificate_serializer = certificate_model.get_certificate_chain_serializers()[0]
        elif file_content == CertificateFileContent.CHAIN_ONLY:
            certificate_serializer = certificate_model.get_certificate_chain_serializers(include_self=False)[0]
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

        self._set_django_http_response(
            data,
            content_type=file_format.mime_type,
            filename='certificate' + file_format.file_extension)



class MultiCertificateDownloadResponseBuilder(DownloadResponseBuilder):

    def __init__(self, pks: list[int | str], file_format: str, file_content: str, archive_format: str) -> None:
        try:
            file_format = CertificateFileFormat(file_format)
        except ValueError:
            raise Http404

        try:
            file_content = CertificateFileContent(file_content)
        except ValueError:
            raise Http404

        try:
            archive_format = CertificateArchiveFormat(archive_format)
        except ValueError:
            raise Http404

        try:
            certificate_models = CertificateModel.objects.filter(pk__in=pks)
        except CertificateModel.DoesNotExist:
            raise Http404

        serializers = []
        if file_content == CertificateFileContent.CERT_ONLY:
            for certificate_model in certificate_models:
                serializers.append(certificate_model.get_certificate_serializer())
        elif file_content == CertificateFileContent.CERT_AND_CHAIN:
            for certificate_model in certificate_models:
                serializers.append(certificate_model.get_certificate_chain_serializers()[0])
        elif file_content == CertificateFileContent.CHAIN_ONLY:
            for certificate_model in certificate_models:
                serializers.append(certificate_model.get_certificate_chain_serializers(include_self=False)[0])

        else:
            raise Http404

        certificate_bytes_collection = []
        if file_format == CertificateFileFormat.PEM:
            for serializer in serializers:
                certificate_bytes_collection.append(serializer.as_pem())
        elif file_content == CertificateFileContent.CERT_ONLY and file_format == CertificateFileFormat.DER:
            for serializer in serializers:
                certificate_bytes_collection.append(serializer.as_der())
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            for serializers in serializers:
                certificate_bytes_collection.append(serializers.as_pkcs7_pem())
        elif file_format == CertificateFileFormat.PKCS7_DER:
            for serializers in serializers:
                certificate_bytes_collection.append(serializers.as_pkcs7_der())
        else:
            raise Http404

        if archive_format == CertificateArchiveFormat.ZIP:
            self._archive_zip(certificate_bytes_collection, file_format)
        elif archive_format == CertificateArchiveFormat.TAR_GZ:
            self._archive_tar_gz(certificate_bytes_collection, file_format)
        else:
            raise Http404

    def _archive_zip(self, certificate_bytes_collection: list[bytes], file_format: CertificateFileFormat) -> None:
        bytes_io = io.BytesIO()
        zip_file = zipfile.ZipFile(bytes_io, 'w')
        for number, cert_bytes in enumerate(certificate_bytes_collection):
            zip_file.writestr(f'certificate-{number}' + file_format.file_extension, cert_bytes)
        zip_file.close()

        self._set_django_http_response(bytes_io.getvalue(), 'application/zip', 'certificates.zip')

    def _archive_tar_gz(self, certificate_bytes_collection: list[bytes], file_format: CertificateFileFormat) -> None:
        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for number, cert_bytes in enumerate(certificate_bytes_collection):
                cert_io_bytes = io.BytesIO(cert_bytes)
                cert_io_bytes_info = tarfile.TarInfo(f'certificate-{number}' + file_format.file_extension)
                cert_io_bytes_info.size = len(cert_bytes)
                tar.addfile(cert_io_bytes_info, cert_io_bytes)

        self._set_django_http_response(bytes_io.getvalue(), 'application/gzip', 'certificates.tar.gz')
