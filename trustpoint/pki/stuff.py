from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


one_day = datetime.timedelta(1, 0, 0)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'cryptography.io'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'cryptography.io'),
    x509.NameAttribute(NameOID.STREET_ADDRESS, 'cryptography.io'),
]))
builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(1)
builder = builder.public_key(public_key)
builder = builder.add_extension(
    x509.SubjectAlternativeName(
        [x509.DNSName('cryptography.io')]
    ),
    critical=False
)
# builder = builder.add_extension(
#     x509.BasicConstraints(), critical=True,
# )
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
)



# with open('test-no-cn.pem', 'rb') as f:
#     cert = f.read()
#
# xcert = x509.load_pem_x509_certificate(cert)
#
# print(xcert.subj
# if xcert.subject:
#     print('ehllo')
# else:
#     print('abc')ect)
#

# if certificate.subject:
#     print('ehllo222')
# else:
#     print('abc222')

for entry in certificate.subject:
    print(entry)
