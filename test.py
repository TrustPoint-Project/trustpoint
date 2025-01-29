from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.x509.oid import NameOID
import datetime


from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc5280

import enum


one_day = datetime.timedelta(1, 0, 0)

# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

private_key = ec.generate_private_key(ec.SECP256R1())

public_key = private_key.public_key()

builder = x509.CertificateBuilder()

builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
]))

builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
]))

builder = builder.not_valid_before(datetime.datetime.today() - one_day)

builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))

builder = builder.serial_number(x509.random_serial_number())

builder = builder.public_key(public_key)

# certificate = builder.sign(
#     private_key=private_key, algorithm=hashes.SHA512(), rsa_padding=padding.PSS(
#         mgf=padding.MGF1(hashes.SHA256()),
#         salt_length=padding.PSS.MAX_LENGTH
#     )
# )

certificate = builder.sign(
    private_key=private_key,
    algorithm=hashes.SHA384(),
)

der_key = certificate.public_key().public_bytes(format=serialization.PublicFormat.SubjectPublicKeyInfo, encoding=serialization.Encoding.DER)
decoded_key, _ = decoder.decode(der_key)
print(decoded_key)
#
# print(dir(certificate.public_key().curve))

# from trustpoint.core.oid import NamedCurve
#
# named_curve = NamedCurve[certificate.public_key().curve.name.upper()]
# print(named_curve)
# print(type(named_curve))

# raw_cert = certificate.public_bytes(encoding=serialization.Encoding.DER)
#
# decoded_cert, _ = decoder.decode(raw_cert, asn1Spec=rfc5280.Certificate())
# print(decoded_cert)
#
# # print(decoded_cert)
# signature_algorithm = decoded_cert['tbsCertificate']['subjectPublicKeyInfo']
# enc_param = encoder.encode(signature_algorithm)
# dec_param, _ = decoder.decode(enc_param)
# print(type(dec_param))
# print(dec_param)
#
#
# class SignatureSuites(enum.Enum):
#     RSA_SHA256 = ('sha256WithRSAEncryption', '1.2.840.113549.1.1.11', )