from __future__ import annotations

import io
import tarfile
import zipfile
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7


class CertificateFileContainer(Enum):
    SINGLE_FILE = 'single_file'
    ZIP = 'zip'
    TAR_GZ = 'tar_gz'


class CertificateChainIncluded(Enum):
    CERT_ONLY = 'cert_only'
    CHAIN_INCL = 'chain_incl'


class CertificateFileFormat(Enum):
    PEM = ('pem', '.pem', 'application/x-pem-file')
    DER = ('der', '.der', 'application/pkix-cert')
    PKCS7 = ('pkcs7_pem', '.p7b', 'application/x-pkcs7-certificates')
    PKCS7_PEM = ('pkcs7_pem', '.p7b', 'application/x-pkcs7-certificates')
    PKCS7_DER = ('pkcs7_der', '.p7b', 'application/x-pkcs7-certificates')
    ZIP = ('zip', '.zip', 'application/zip')
    TAR_GZ = ('tar_gz', '.tar.gz', 'application/x-gtar')

    def __new__(cls, value, file_extension, mime_type):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.file_extension = file_extension
        obj.mime_type = mime_type
        return obj

    @classmethod
    def get_by_file_name_with_extension(cls, filename: str) -> CertificateFileFormat:
        filename = filename.lower()
        if filename.endswith('.pem') or filename.endswith('.crt') or filename.endswith('.ca-bundle'):
            return cls.PEM
        if filename.endswith('.der') or filename.endswith('.cer'):
            return cls.DER
        if filename.endswith('.p7b') or filename.endswith('.p7c') or filename.endswith('.keystore'):
            return cls.PKCS7
        if filename.endswith('.zip'):
            return cls.ZIP
        if filename.endswith('.tar.gz'):
            return cls.TAR_GZ
        else:
            raise ValueError('Failed to find a MimeType for the given filename and extension.')


class CertificateFileGenerator:

    @classmethod
    def generate(
            cls,
            certs: list[Certificate],
            cert_file_container: CertificateFileContainer,
            cert_chain_incl: CertificateChainIncluded,
            cert_file_format: CertificateFileFormat) -> tuple[bytes, str]:

        cls._check_certs_not_empty(certs)

        if cert_file_container == CertificateFileContainer.SINGLE_FILE:
            return cls._generate_single_file(
                certs=certs,
                cert_chain_included=cert_chain_incl,
                cert_file_format = cert_file_format
            )
        else:
            return cls._generate_separate_files(
                certs=certs,
                cert_file_container=cert_file_container,
                cert_chain_included=cert_chain_incl,
                cert_file_format=cert_file_format
            )

    @staticmethod
    def _get_certs_with_chains(certs: list[Certificate]) -> list[Certificate]:
        new_certs = []
        for cert in certs:
            new_certs.extend(cert.get_cert_chain())
        # removes duplicates
        return list(set(new_certs))

    @staticmethod
    def _get_certs_with_chains_nested(certs: list[Certificate]) -> list[list[Certificate]]:
        new_certs = []
        for cert in certs:
            new_certs.append(cert.get_cert_chain())
        return new_certs

    @classmethod
    def _generate_single_file(
            cls,
            certs: list[Certificate],
            cert_file_format: CertificateFileFormat,
            cert_chain_included: CertificateChainIncluded) -> tuple[bytes, str]:

        if cert_chain_included == CertificateChainIncluded.CHAIN_INCL:
            certs = cls._get_certs_with_chains(certs=certs)

        if len(certs) == 1:
            filename = 'certificate'
        else:
            filename = 'certificates'

        if cert_file_format == CertificateFileFormat.PEM:
            return cls._generate_pem(certs=certs), filename + '.pem'

        elif cert_file_format == CertificateFileFormat.DER:
            return cls._generate_der(certs=certs), filename + '.der'

        elif cert_file_format == CertificateFileFormat.PKCS7_PEM:
            return cls._generate_pkcs7_pem(certs=certs), filename + '.p7b'

        elif cert_file_format == CertificateFileFormat.PKCS7_DER:
            return cls._generate_pkcs7_der(certs=certs), filename + '.p7b'

        raise ValueError(f'Unsupported file format found: {cert_file_format.value}.')

    @classmethod
    def _generate_separate_files(
            cls,
            certs: list[Certificate],
            cert_file_container: CertificateFileContainer,
            cert_file_format: CertificateFileFormat,
            cert_chain_included: CertificateChainIncluded) -> tuple[bytes, str]:

        filenames = []
        for cert in certs:
            filenames.append(f'certificate_{cert.serial_number}')

        if cert_chain_included == CertificateChainIncluded.CHAIN_INCL:
            certs = cls._get_certs_with_chains_nested(certs=certs)

        cert_bytes = []
        if cert_file_format == CertificateFileFormat.PEM:
            for index, cert in enumerate(certs):
                cert_bytes.append((cls._generate_pem(cert), filenames[index]))

        if cert_file_format == CertificateFileFormat.DER:
            for index, cert in enumerate(certs):
                cert_bytes.append((cls._generate_der(cert), filenames[index]))

        if cert_file_format == CertificateFileFormat.PKCS7_PEM:
            for index, cert in enumerate(certs):
                cert_bytes.append((cls._generate_pkcs7_pem(cert), filenames[index]))

        if cert_file_format == CertificateFileFormat.PKCS7_DER:
            for index, cert in enumerate(certs):
                cert_bytes.append((cls._generate_pkcs7_der(cert), filenames[index]))

        if cert_file_container == CertificateFileContainer.ZIP:
            return cls._generate_zip(cert_raw_bytes=cert_bytes, file_extension=cert_file_format.file_extension)
        if cert_file_container == CertificateFileContainer.TAR_GZ:
            return cls._generate_tar_gz(cert_raw_bytes=cert_bytes, file_extension=cert_file_format.file_extension)

    @classmethod
    def _generate_zip(cls, cert_raw_bytes: list[tuple[bytes, str]], file_extension: str) -> tuple[bytes, str]:
        bytes_io = io.BytesIO()
        zip_file = zipfile.ZipFile(bytes_io, 'w')
        for cert_bytes, filename in cert_raw_bytes:
            zip_file.writestr(filename + file_extension, cert_bytes)
        zip_file.close()
        return bytes_io.getvalue(), 'certificates.zip'

    @classmethod
    def _generate_tar_gz(cls, cert_raw_bytes: list[tuple[bytes, str]], file_extension: str) -> tuple[bytes, str]:
        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for cert_bytes, filename in cert_raw_bytes:
                cert_bytes_file = io.BytesIO(initial_bytes=cert_bytes)
                cert_bytes_file_info = tarfile.TarInfo(filename + file_extension)
                cert_bytes_file_info.size = len(cert_bytes)
                tar.addfile(cert_bytes_file_info, cert_bytes_file)
        return bytes_io.getvalue(), 'certificates.tar.gz'

    @staticmethod
    def _check_certs_not_empty(certs: list[Certificate]) -> None:
        if len(certs) == 0:
            raise ValueError('No certificates found. Nothing to generate.')

    @staticmethod
    def _generate_pem(certs: Certificate | list[Certificate]) -> bytes:
        if isinstance(certs, Certificate):
            return certs.get_cert_as_pem()
        pem = b''
        for cert in certs:
            pem += cert.get_cert_as_pem()
        return pem

    @staticmethod
    def _generate_der(certs: Certificate | list[Certificate]) -> bytes:
        if isinstance(certs, Certificate):
            return certs.get_cert_as_der()
        if len(certs) != 1:
            raise ValueError(
                f'DER format can only store a single certificate, but found {len(certs)} certificates.')
        return certs[0].get_cert_as_der()

    @staticmethod
    def _get_crypto_certs(certs: Certificate | list[Certificate]) -> list[x509.Certificate]:
        if isinstance(certs, Certificate):
            return [certs.get_cert_as_crypto()]
        crypto_certs = []
        for cert in certs:
            crypto_certs.append(cert.get_cert_as_crypto())
        return crypto_certs

    @classmethod
    def _generate_pkcs7_pem(cls, certs: Certificate | list[Certificate]) -> bytes:
        new_certs = cls._get_crypto_certs(certs=certs)
        return pkcs7.serialize_certificates(new_certs, encoding=Encoding.PEM)

    @classmethod
    def _generate_pkcs7_der(cls, certs: Certificate | list[Certificate]) -> bytes:
        new_certs = cls._get_crypto_certs(certs=certs)
        return pkcs7.serialize_certificates(new_certs, encoding=Encoding.DER)
