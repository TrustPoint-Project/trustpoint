from __future__ import annotations

import datetime
from abc import ABC, abstractmethod

# from devices.models import Device
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateRevocationListBuilder, ReasonFlags, load_pem_x509_crl
from django.conf import settings
from django.db import transaction

from .serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
    PublicKeySerializer,
)

if TYPE_CHECKING:
    from typing import Union

    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from cryptography.x509 import CertificateRevocationList

    from .models import CertificateModel, IssuingCaModel
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


class IssuingCa(ABC):
    _issuing_ca_model: IssuingCaModel

    # @abstractmethod
    # def issue_ldevid(self, device: Device):
    #     pass

    # @abstractmethod
    # def issue_certificate(self, *args, **kwargs) -> CertificateModel:
    #     pass
    #
    # @abstractmethod
    # def sign_crl(self, *args, **kwargs) -> Any:
    #     pass


class UnprotectedLocalIssuingCa(IssuingCa):

    _issuing_ca_model: IssuingCaModel
    _private_key_serializer: PrivateKeySerializer
    _builder: CertificateRevocationListBuilder

    def __init__(self, issuing_ca_model: IssuingCaModel) -> None:
        super().__init__()
        self._issuing_ca_model = issuing_ca_model
        self._private_key_serializer = self._get_private_key_serializer()
        ca_serializer = self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto()
        self.crl_builder = CertificateRevocationListBuilder(
            issuer_name=ca_serializer.issuer,
            last_update=datetime.datetime.today(),
            next_update=datetime.datetime.today() + datetime.timedelta(hours=settings.CRL_INTERVAL)
        )

    def _parse_existing_crl(self):
        from .models import CRLStorage
        crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        if crl:
            return load_pem_x509_crl(crl.encode('utf-8'))
        return []

    def _get_private_key_serializer(self) -> PrivateKeySerializer:
        return PrivateKeySerializer.from_string(self._issuing_ca_model.private_key_pem)

    def _build_revoked_cert(self, revocation_datetime, cert: CertificateModel):
        return x509.RevokedCertificateBuilder().serial_number(
                    int(cert.serial_number, 16)
                ).revocation_date(
                    revocation_datetime
                ).add_extension(
                    x509.CRLReason(ReasonFlags(cert.revocation_reason)), critical=False
                ).build()

    def generate_crl(self) -> bool:
        # TODO: this should not take an crl_builder object, but instead get the crl information required from the
        # TODO: issuing ca model / crl model and sign the crl as below.
        from .models import RevokedCertificate
        with transaction.atomic():

            revoked_certificates = self._parse_existing_crl()
            for cert in revoked_certificates:
                self.crl_builder.add_revoked_certificate(cert)

            revoked_certificates = RevokedCertificate.objects.filter(issuing_ca=self._issuing_ca_model)

            for entry in revoked_certificates:
                revoked_cert = self._build_revoked_cert(entry.revocation_datetime, entry.cert)
                self.crl_builder = self.crl_builder.add_revoked_certificate(revoked_cert)
            crl = self.crl_builder.sign(private_key=self._private_key_serializer.as_crypto(), algorithm=hashes.SHA256())
            self.save_crl_to_database(crl.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'))
            revoked_certificates.delete()
        return True

    def save_crl_to_database(self, crl: CertificateRevocationList) -> None:
        from .models import CRLStorage
        """Some"""
        CRLStorage.objects.update_or_create(
            crl=crl,
            ca=self._issuing_ca_model
        )

    def get_crl(self):
        from .models import CRLStorage
        crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        if crl is None:
            self.generate_crl()
            crl = CRLStorage.get_crl(ca=self._issuing_ca_model)
        return crl

    def get_ca_name(self):
        return self._issuing_ca_model.unique_name

    # def issue_ldevid(self, device: Device):
    #     pass

    # def issue_certificate(self, *args, **kwargs) -> CertificateModel:
    #     pass
    #
    # def sign_crl(self, *args, **kwargs) -> Any:
    #     pass
