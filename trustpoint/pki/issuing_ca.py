from __future__ import annotations

import logging
from abc import ABC
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.db import transaction

from .serializer import CertificateCollectionSerializer, PrivateKeySerializer
from .models.text_choice import CertificateStatus, ReasonCode
from .util.keys import SignatureSuite

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from .models import CertificateModel, BaseCaModel, RevokedCertificate, CRLStorage
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    from serializer import CertificateSerializer, PublicKeySerializer


log = logging.getLogger('tp.pki')


class IssuingCa(ABC):
    _issuing_ca_model: BaseCaModel

    def get_issuing_ca_certificate(self) -> CertificateModel:
        return self._issuing_ca_model.get_issuing_ca_certificate()

    def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer()

    def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
        return self._issuing_ca_model.get_issuing_ca_public_key_serializer()

    def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain()

    def get_issuing_ca_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain_serializer()

    @property
    def issuing_ca_model(self) -> BaseCaModel:
        return self._issuing_ca_model


class UnprotectedLocalIssuingCa(IssuingCa):

    _private_key: None | PrivateKey = None
    _builder: x509.CertificateRevocationListBuilder

    def __init__(self, issuing_ca_model: BaseCaModel, *args, **kwargs) -> None:
        """Initializes an UnprotectedLocalIssuingCa instance.

        Args:
            issuing_ca_model (BaseCaModel): The issuing CA model instance
            representing the CA for which the CRL is being managed.
        """
        super().__init__(*args, **kwargs)
        self._issuing_ca_model = issuing_ca_model
        self._private_key_serializer = self._get_private_key_serializer()
        ca_serializer = self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto()
        self.crl_builder = x509.CertificateRevocationListBuilder(
            issuer_name=ca_serializer.issuer,
            last_update=datetime.now(),
            next_update=datetime.now() + timedelta(minutes=issuing_ca_model.next_crl_generation_time)
        )
        log.debug('UnprotectedLocalIssuingCa initialized.')

    @property
    def issuer_name(self) -> x509.Name:
        # TODO: store issuer and subject bytes in DB
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto().issuer

    @property
    def subject_name(self) -> x509.Name:
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto().subject

    @property
    def private_key(self) -> PrivateKey:
        if self._private_key is None:
            self._private_key = PrivateKeySerializer(self._issuing_ca_model.private_key_pem).as_crypto()
        return self._private_key

    def _get_private_key_serializer(self) -> PrivateKeySerializer:
        """Retrieves the private key serializer for the issuing CA.

        Returns:
            PrivateKeySerializer: A serializer instance for the CA's private key.
        """
        return PrivateKeySerializer(self._issuing_ca_model.private_key_pem)

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

            revoked_certificates = self.get_crl_as_x509()
            if revoked_certificates:
                for cert in revoked_certificates:
                    self.crl_builder = self.crl_builder.add_revoked_certificate(cert)

            revoked_certificates = RevokedCertificate.objects.filter(issuing_ca=self._issuing_ca_model)

            for entry in revoked_certificates:
                revoked_cert = self._build_revoked_cert(entry.revocation_datetime, entry.cert)
                self.crl_builder = self.crl_builder.add_revoked_certificate(revoked_cert)
            log.debug('CRL generation finished. Starting signing.')
            hash_algorithm = SignatureSuite.get_hash_algorithm_by_key(
                self._issuing_ca_model.get_issuing_ca_public_key_serializer().as_crypto())
            crl = self.crl_builder.sign(private_key=self._private_key_serializer.as_crypto(), algorithm=hash_algorithm)
            log.debug('CRL signing finished.')
            self.save_crl_to_database(crl.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'))
            revoked_certificates.delete()
            log.info('CRL generation finished.')
        return True

    def get_creation_date_from_crl(self, crl) -> datetime:
        crl = x509.load_pem_x509_crl(crl.encode())
        return crl.last_update_utc


    def save_crl_to_database(self, crl: x509.CertificateRevocationList) -> None:
        """Saves the generated CRL to the database.

        Args:
            crl (str): The CRL in PEM format to be stored in the database.
        """
        from .models import CRLStorage
        CRLStorage.objects.create(
            crl=crl,
            created_at = self.get_creation_date_from_crl(crl),
            ca=self._issuing_ca_model
        )
        log.info('CRL stored in Database.')

    def get_crl_as_str(self) -> str:
        """Retrieves the current CRL for the issuing CA.

        Returns:
            str: The CRL in PEM format.
        """
        from .models import CRLStorage
        return CRLStorage.get_crl(ca=self._issuing_ca_model)

    def get_crl_as_x509(self) -> None | x509.CertificateRevocationList:
        """Retrieves the current CRL for the issuing CA.

        Returns:
            CertificateRevocationList: The CRL as x509 object.
        """
        crl = self.get_crl_as_str()
        if crl:
            return x509.load_pem_x509_crl(crl.encode())
        return None

    def get_crl_entry(self) -> CRLStorage:
        """Retrieves the current CRL for the issuing CA.

        Returns:
            str: The CRL in PEM format.
        """
        from .models import CRLStorage
        return CRLStorage.get_crl_object(ca=self._issuing_ca_model)
    
    def revoke_all_certificates(self) -> None:
        """Revokes all certificates issued by the CA."""
        log.info('Revoking all certificates issued by the CA %s.', self._issuing_ca_model.unique_name)
        # Disable auto CRL generation so we don't generate a CRL for each revocation
        auto_crl_state = self._issuing_ca_model.auto_crl
        self._issuing_ca_model.auto_crl = False
        self._issuing_ca_model.save()
        # Get all non-revoked certificates issued by the CA
        issued_certs = self.get_issuing_ca_certificate().issued_certificate_references.exclude(
                            certificate_status=CertificateStatus.REVOKED)
        # Check if any certificates are device LDevIDs, in that case revoke via device
        for cert in issued_certs:
            if cert.device_set.exists():
                for device in cert.device_set.all():
                    device.revoke_ldevid(revocation_reason=ReasonCode.CESSATION)
            else:  # Revoke the certificate directly
                cert.revoke(revocation_reason=ReasonCode.CESSATION)

        self.generate_crl()
        self._issuing_ca_model.auto_crl = auto_crl_state
        self._issuing_ca_model.save()

    def get_ca_name(self) -> str:
        """Retrieves the unique name of the issuing CA.

        Returns:
            str: The unique name of the CA.
        """
        return self._issuing_ca_model.unique_name
