"""Module that contains all models corresponding to the PKI app."""


from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.validator.field import UniqueNameValidator
from pki.models.certificate import CertificateModel
from core.serializer import PublicKeySerializer, CertificateCollectionSerializer, CertificateSerializer
from pki.issuing_ca import UnprotectedLocalIssuingCa

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


__all__ = [
    # 'CertificateAuthority',
    # 'ProxyManager',
    # 'BaseCaModel',
    # 'IssuingCaModel',
    # 'RootCaModel',
    # 'CertificateChainOrderModel',
]


# class CertificateAuthority(models.Model):
#
#     class CaType(models.TextChoices):
#         ROOT_CA = 'ROOT_CA'
#         INTERMEDIATE_CA = 'INTERMEDIATE_CA'
#         ISSUING_CA = 'ISSUING_CA'
#
#
# class ProxyManager(models.Manager):
#     def get_queryset(self):
#         return super().get_queryset().filter(proxy_name=self.model.__name__)
#
# class BaseCaModel(models.Model):
#     """Base CA model for both Issuing and local Root CAs."""
#
#     class CaLocalization(models.TextChoices):
#         """The localization of the CA.
#
#         Auto-Gen PKI is a special case of the local CA, where the root CA is self-signed by the system.
#         """
#         LOCAL = "local", _('Local')
#         REMOTE = "remote", _('Remote')
#         AUTO_GEN_PKI = "autogen", _('AutoGenPKI')
#
#     proxy_name = models.CharField(max_length=20) # to distinguish between Issuing and Root CA classes
#
#     unique_name = models.CharField(
#         verbose_name=_('Unique Name'),
#         max_length=100,
#         validators=[UniqueNameValidator()],
#         unique=True,
#         editable=False
#     )
#
#     ca_localization = models.CharField(max_length=8, choices=CaLocalization, default=CaLocalization.LOCAL)
#
#     root_ca_certificate = models.ForeignKey(
#         to=CertificateModel,
#         verbose_name=_('Root CA Certificate'),
#         on_delete=models.DO_NOTHING,
#         related_name='root_ca_certificate',
#         editable=False
#     )
#
#     intermediate_ca_certificates = models.ManyToManyField(
#         to=CertificateModel,
#         verbose_name=_('Intermediate CA Certificates'),
#         through='CertificateChainOrderModel')
#
#     issuing_ca_certificate = models.OneToOneField(
#         to=CertificateModel,
#         verbose_name=_('Issuing CA Certificate'),
#         on_delete=models.DO_NOTHING,
#         related_name='issuing_ca_model',
#         editable=False)
#
#     private_key_pem = models.CharField(
#         verbose_name=_('Private Key (PEM)'),
#         max_length=65536,
#         editable=False,
#         null=True,
#         blank=True,
#         unique=True)
#
#     added_at = models.DateTimeField(verbose_name=_('Added at'), auto_now_add=True)
#
#     issued_certificates_count = models.PositiveIntegerField(default=0, editable=False)
#
#     def __str__(self) -> str:
#         return self.unique_name
#
#     def get_issuing_ca_certificate(self) -> CertificateModel:
#         return self.issuing_ca_certificate
#
#     def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
#         return self.issuing_ca_certificate.get_certificate_serializer()
#
#     def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
#         return self.issuing_ca_certificate.get_public_key_serializer()
#
#     def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
#         # TODO: through table -> order_by order
#         cert_chain = [self.root_ca_certificate]
#         # print(self.intermediate_ca_certificates.all())
#         # cert_chain.extend(self.intermediate_ca_certificates.all().order_by('order').asc())
#         cert_chain.append(self.issuing_ca_certificate)
#         return cert_chain
#
#     def get_issuing_ca_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
#         return CertificateCollectionSerializer(
#             [cert.get_certificate_serializer().as_crypto() for cert in self.get_issuing_ca_certificate_chain()])
#
#     def get_issuing_ca(self) -> UnprotectedLocalIssuingCa:
#         if self.private_key_pem:
#             return UnprotectedLocalIssuingCa(self)
#         raise RuntimeError('Unexpected error occurred. No matching IssuingCa object found.')
#
#     def increment_issued_certificates_count(self) -> None:
#         """Increments issued_certificates_count by one"""
#         #self.issued_certificates_count = models.F('issued_certificates_count') + 1
#         self.issued_certificates_count += 1
#         self.save(update_fields=['issued_certificates_count'])
#
#     def save(self, *args, **kwargs):
#         self.proxy_name = type(self).__name__
#         self.full_clean()
#         super().save(*args, **kwargs)
#
#
# class RootCaModel(BaseCaModel):
#     """Root CA model.
#
#     Functionally equivalent to IssuingCaModel, but not part of issuing CA list and cannot be edited externally.
#     """
#     class Meta:
#         proxy = True
#
#     objects = ProxyManager()
#
# class IssuingCaModel(BaseCaModel):
#     """Issuing CA model."""
#     class Meta:
#         proxy = True
#
#     objects = ProxyManager()
#
# class CertificateChainOrderModel(models.Model):
#
#     class Meta:
#         unique_together = ('order', 'issuing_ca')
#
#     order = models.PositiveSmallIntegerField(verbose_name=_('Intermediate CA Index (Order)'), editable=False)
#     certificate = models.ForeignKey(
#         CertificateModel,
#         on_delete=models.CASCADE,
#         editable=False,
#         related_name='issuing_ca_cert_chains')
#     issuing_ca = models.ForeignKey(BaseCaModel, on_delete=models.CASCADE, editable=False)
#
#     def __str__(self):
#         return f'CertificateChainOrderModel({self.certificate.common_name})'
