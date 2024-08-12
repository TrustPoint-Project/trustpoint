from __future__ import annotations

import datetime
import logging
from abc import ABC

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from django.conf import settings
from django.db import transaction

from .serialization.serializer import PrivateKeySerializer

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from .models import CertificateModel, IssuingCaModel, RevokedCertificate, CRLStorage
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    from serialization.serializer import CertificateSerializer, PublicKeySerializer, CertificateCollectionSerializer


log = logging.getLogger('tp.pki')


class IssuingCa(ABC):
    _issuing_ca_model: IssuingCaModel

    def get_issuing_ca_certificate(self) -> CertificateModel:
        return self._issuing_ca_model.get_issuing_ca_certificate()

    def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer()

    def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
        return self._issuing_ca_model.get_issuing_ca_public_key_serializer()

    def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain()

    def get_issuing_ca_certificate_chain_serializer(
            self,
            certificate_chain_serializer: type(CertificateCollectionSerializer) = CertificateCollectionSerializer
    ) -> CertificateCollectionSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain_serializer(certificate_chain_serializer)


class UnprotectedLocalIssuingCa(IssuingCa):

    _private_key: None | PrivateKey = None
    _builder: x509.CertificateRevocationListBuilder

    def __init__(self, issuing_ca_model: IssuingCaModel, *args, **kwargs) -> None:
        """Initializes an UnprotectedLocalIssuingCa instance.

        Args:
            issuing_ca_model (IssuingCaModel): The issuing CA model instance
            representing the CA for which the CRL is being managed.
        """
        super().__init__(*args, **kwargs)
        self._issuing_ca_model = issuing_ca_model
        self._private_key_serializer = self._get_private_key_serializer()
        ca_serializer = self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto()
        self.crl_builder = x509.CertificateRevocationListBuilder(
            issuer_name=ca_serializer.issuer,
            last_update=datetime.datetime.today(),
            next_update=datetime.datetime.today() + datetime.timedelta(hours=settings.CRL_INTERVAL)
        )
        log.debug('UnprotectedLocalIssuingCa initialized.')

    @property
    def issuer_name(self) -> x509.Name:
        # TODO: store issuer and subject bytes in DB
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto().issuer

    @property
    def private_key(self) -> PrivateKey:
        if self._private_key is None:
            self._private_key = PrivateKeySerializer.from_string(self._issuing_ca_model.private_key_pem).as_crypto()
        return self._private_key

    def _parse_existing_crl(self) -> list | x509.CertificateRevocationList:
        """Parses the existing CRL for the associated CA.

        Retrieves the stored CRL from the database and loads it using the x509
        library. If no CRL exists, returns an empty list.

        Returns:
            (CertificateRevocation)list: A list of revoked certificates if a CRL is found, otherwise
            an empty list.
        """
        from .models import CRLStorage
        crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        if crl:
            log.debug('CRL found in database and started parsing.')
            return x509.load_pem_x509_crl(crl.encode())
        log.debug('No CRL found in database.')
        return []

    def _get_private_key_serializer(self) -> PrivateKeySerializer:
        """Retrieves the private key serializer for the issuing CA.

        Returns:
            PrivateKeySerializer: A serializer instance for the CA's private key.
        """
        return PrivateKeySerializer.from_string(self._issuing_ca_model.private_key_pem)

    @staticmethod
    def _build_revoked_cert(revocation_datetime: datetime, cert: CertificateModel) -> RevokedCertificate:
        """Builds a revoked certificate entry for inclusion in the CRL.

        Args:
            revocation_datetime (datetime): The date and time when the certificate
                was revoked.
            cert (CertificateModel): The certificate model instance representing
                the certificate to be revoked.

        Returns:
            x509.RevokedCertificate: The constructed revoked certificate entry.
        """
        return x509.RevokedCertificateBuilder().serial_number(
            int(cert.serial_number, 16)).revocation_date(
                revocation_datetime).add_extension(x509.CRLReason(
                    x509.ReasonFlags(cert.revocation_reason)), critical=False).build()

    def generate_crl(self) -> bool:
        """Generates a new CRL and updates the database with the latest entries.

        This method processes existing revoked certificates, adds them to the
        CRL builder, signs the CRL, and stores it in the database. It ensures
        atomicity of database operations.
        """
        from .models import RevokedCertificate
        with transaction.atomic():
            log.debug('Started CRL generation.')

            revoked_certificates = self._parse_existing_crl()
            for cert in revoked_certificates:
                self.crl_builder = self.crl_builder.add_revoked_certificate(cert)

            revoked_certificates = RevokedCertificate.objects.filter(issuing_ca=self._issuing_ca_model)

            for entry in revoked_certificates:
                revoked_cert = self._build_revoked_cert(entry.revocation_datetime, entry.cert)
                self.crl_builder = self.crl_builder.add_revoked_certificate(revoked_cert)
            log.debug('CRL generation finished. Starting signing.')
            crl = self.crl_builder.sign(private_key=self._private_key_serializer.as_crypto(), algorithm=hashes.SHA256())
            log.debug('CRL signing finished.')
            self.save_crl_to_database(crl.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'))
            revoked_certificates.delete()
            log.info('CRL generation finished.')
        return True

    def save_crl_to_database(self, crl: x509.CertificateRevocationList) -> None:
        """Saves the generated CRL to the database.

        Args:
            crl (str): The CRL in PEM format to be stored in the database.
        """
        from .models import CRLStorage
        CRLStorage.objects.update_or_create(
            crl=crl,
            ca=self._issuing_ca_model
        )
        log.info('CRL stored in Database.')

    def get_crl(self) -> str:
        """Retrieves the current CRL for the issuing CA.

        If no CRL is present, generates a new one and returns it.

        Returns:
            str: The CRL in PEM format.
        """
        from .models import CRLStorage
        crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        if crl is None:
            self.generate_crl()
            crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        return crl

    def get_crl_entry(self) -> CRLStorage:
        """Retrieves the current CRL for the issuing CA.

        If no CRL is present, generates a new one and returns it.

        Returns:
            str: The CRL in PEM format.
        """
        from .models import CRLStorage
        return CRLStorage.get_crl_entry(ca=self._issuing_ca_model)

    def get_ca_name(self) -> str:
        """Retrieves the unique name of the issuing CA.

        Returns:
            str: The unique name of the CA.
        """
        return self._issuing_ca_model.unique_name
