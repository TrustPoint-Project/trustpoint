from __future__ import annotations

from abc import ABC, abstractmethod
from .models import CertificateModel, IssuingCaModel
from .serializer import CertificateSerializer, CertificateChainSerializer, PublicKeySerializer


from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


class IssuingCA(ABC):
    _issuing_ca_model: IssuingCaModel

    @abstractmethod
    def issue_certificate(self, *args, **kwargs) -> CertificateModel:
        pass

    @abstractmethod
    def sign_crl(self, *args, **kwargs) -> Any:
        pass

    def get_issuing_ca_certificate(self) -> CertificateModel:
        return self._issuing_ca_model.issuing_ca_certificate

    def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
        return self._issuing_ca_model.issuing_ca_certificate.get_certificate_serializer()

    def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
        return self._issuing_ca_model.issuing_ca_certificate.get_public_key_serializer()

    def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
        cert_chain = [self._issuing_ca_model.root_ca_certificate]
        cert_chain.extend(self._issuing_ca_model.intermediate_ca_certificates.all().order_by('order').asc())
        cert_chain.append(self._issuing_ca_model.issuing_ca_certificate)
        return cert_chain

    def get_issuing_ca_certificate_chain_serializer(
            self,
            certificate_chain_serializer: type(CertificateChainSerializer) = CertificateSerializer
    ) -> CertificateChainSerializer:
        return certificate_chain_serializer(
            [cert.get_certificate_serializer().get_as_crypto() for cert in self.get_issuing_ca_certificate_chain()])




