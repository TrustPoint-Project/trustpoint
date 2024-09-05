from __future__ import annotations

from sys import exc_info

from cryptography.hazmat.primitives import hashes
from django.db import transaction
from cryptography import x509


from pki.models import (
    CertificateModel,
    TrustStoreModel,
    TrustStoreOrderModel)


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


__all__ = [
    'TrustStoreInitializer'
]


class TrustStoreInitializer:
    _unique_name: str
    _trust_store: list[x509.Certificate]
    _cert_model_class: type(CertificateModel) = CertificateModel
    _trust_store_model_class: type(TrustStoreModel) = TrustStoreModel
    _trust_store_order_model_class: type(TrustStoreOrderModel) = TrustStoreOrderModel

    def __init__(self, unique_name: str, trust_store: bytes | list[x509.Certificate]) -> None:

        if isinstance(trust_store, bytes):
            trust_store = x509.load_pem_x509_certificates(trust_store)

        self._unique_name = unique_name
        self._trust_store = trust_store

    @transaction.atomic
    def save(self):

        saved_certs = []


        for certificate in self._trust_store:
            sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()
            print(f'fingerprint {sha256_fingerprint}')
            try:
                print('trying')
                saved_certs.append(CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint))
                print('yes')
            except CertificateModel.DoesNotExist:
                print('nope')
                saved_certs.append(self._cert_model_class.save_certificate(certificate))
            except Exception as e:
                print(e)
                print(type(e))
                print(exc_info())

        trust_store_model = self._trust_store_model_class(unique_name=self._unique_name)
        trust_store_model.save()

        for number, certificate in enumerate(saved_certs):
            _trust_store_order_model = self._trust_store_order_model_class()
            _trust_store_order_model.order = number
            _trust_store_order_model.certificate = certificate
            _trust_store_order_model.trust_store = trust_store_model
            _trust_store_order_model.save()