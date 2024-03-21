from __future__ import annotations
from ninja import Router, ModelSchema
from .models import IssuingCa as IssuingCaModel, TestB
from django.http import HttpResponse
from .schema import Certificate
from django.shortcuts import get_object_or_404
from util.x509.enums import SignatureAlgorithmOid


class IssuingCa(ModelSchema):
    class Meta:
        model = IssuingCaModel
        fields = (
            'id',
            'unique_name',
            'common_name',
            'key_type',
            'key_size',
            'curve',
            'localization',
            'config_type')


class TestBSchema(ModelSchema):

    class Meta:
        model = TestB
        fields = ('b',)

    test_a: TestBSchema | None = None


router = Router()


@router.get('/issuing-cas/{pk}', response=TestBSchema)
def list_issuing_cas(request: HttpResponse, pk: int):
    """Returns a list of all Issuing CAs as JSON.

    It contains general information, but does not contain the actual certificates.
    """
    test = get_object_or_404(TestB, id=pk)
    return TestBSchema(b=test.b, test_a=test.test_a)


# -------------------------------------------------- EndpointProfiles --------------------------------------------------

# @router.get('/endpoint-profiles/list', response=Certificate)
# def ep_list(request):
#     c = Certificate(version=2, serial_number=125425, not_valid_before=datetime.now(), not_valid_after=datetime.now())
#     return c

# @router.get('/endpoint-profiles/details/{pk}/')
# def ep_details(request, pk):

# @router.get('/details/<int:pk>')
# def details

# ----------------------------------------------------- IssuingCas -----------------------------------------------------

# @router.get('/issuing-cas/list')
# def ep_list(request):
#     a = {
#         'keyOne': 'ValueOne',
#         'KeyTwo': 10,
#         'KeyThree': True
#     }
#     return a

# @router.get('/issuing-cas', response=list[IssuingCa])
# def list_issuing_cas(request: HttpResponse):
#     """Returns a list of all Issuing CAs as JSON.
#
#     It contains general information, but does not contain the actual certificates.
#     """
#     return IssuingCaModel.objects.all()
#
#
# @router.get('/issuing-cas/{pk}',  response=list[Certificate])
# def list_issuing_cas(request: HttpResponse, pk: int):
#     """Returns a list of all Issuing CAs as JSON.
#
#     It contains general information, but does not contain the actual certificates.
#
#     The first certificate will be the Root CA certificate, followed by any possible intermediate certificates.
#     The last certificate will be the actual Issuing CA certificate.
#     """
#     issuing_ca = get_object_or_404(IssuingCaModel, id=pk)
#     cert_chain = issuing_ca.get_crypto_cert_chain()
#
#     json_cert_chain = []
#
#     for cert in cert_chain:
#         print(hex(cert.serial_number))
#         print(type(cert.serial_number))
#
#         json_cert_chain.append(Certificate(
#             version=cert.version.value,
#             serial_number=hex(cert.serial_number),
#             not_valid_before=cert.not_valid_before,
#             not_valid_after=cert.not_valid_after,
#             signature_algorithm=SignatureAlgorithmOid(cert.signature_algorithm_oid.dotted_string)))
#
#     return json_cert_chain
