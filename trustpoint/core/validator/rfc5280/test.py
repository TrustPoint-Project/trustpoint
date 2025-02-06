import re
from datetime import datetime, timezone

from cryptography.x509 import load_pem_x509_certificate

from core.validator.rfc5280.validator import (
    AuthorityKeyIdentifierValidation,
    BasicConstraintsValidation,
    CertificatePoliciesValidation,
    CompositeValidation,
    CRLDistributionPointsValidation,
    ExtendedKeyUsageValidation,
    FreshestCRLValidation,
    InhibitAnyPolicyValidation,
    IssuerAlternativeNameValidation,
    IssuerValidation,
    KeyUsageValidation,
    NameConstraintsValidation,
    PolicyConstraintsValidation,
    SANAttributesValidation,
    SerialNumberValidation,
    SignatureValidation,
    SubjectAlternativeNameValidation,
    SubjectAttributesValidation,
    SubjectDirectoryAttributesValidation,
    SubjectKeyIdentifierValidation,
    SubjectPublicKeyInfoValidation,
    SubjectValidation,
    UniqueIdentifiersValidation,
    ValidityValidation,
)

ca_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIG4jCCBMqgAwIBAgIUe65aHlOj4r3BRajNxR3uC4ZChyMwDQYJKoZIhvcNAQEL
BQAwgYwxJDAiBgNVBAMMG1JTQSBQaG9lbml4IENvbnRhY3QgUm9vdC1DQTEmMCQG
A1UECgwdUGhvZW5peCBDb250YWN0IEdtYkggJiBDby4gS0cxETAPBgNVBAcMCEJs
b21iZXJnMRwwGgYDVQQIDBNOb3JkcmhlaW4tV2VzdGZhbGVuMQswCQYDVQQGEwJE
RTAeFw0yMTEyMDkxMDEyNDhaFw0yNjEyMDgxMDEyNDdaMIGMMSQwIgYDVQQDDBtS
U0EgUGhvZW5peCBDb250YWN0IFJvb3QtQ0ExJjAkBgNVBAoMHVBob2VuaXggQ29u
dGFjdCBHbWJIICYgQ28uIEtHMREwDwYDVQQHDAhCbG9tYmVyZzEcMBoGA1UECAwT
Tm9yZHJoZWluLVdlc3RmYWxlbjELMAkGA1UEBhMCREUwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCZGjApRor+NB9tDtMzhH3gz+eDjraYkX+wOjDkLiJb
roIGdOQQ82cdnjxWsPNr5Muv0u0pTa/QCBpRGahr5WRHxWlGgmVS8t+VY7c43wBF
ocDK1lNvGmPxkWYzfslTwZ/g1laXNJEKsBgW4H2ozdWNqkLpUcRxYvez41IWsdgY
6myOLcQQiSkP17RlplYmVYJO4uknt8EyeBsJvqJeFw+ArZxarSAxQQUwD1TLcyb4
KO0Ef4dWuVRcfT2eY/B1mXF3y44tAmHH0sHONQNwEYeskJF9xT25k0gIkPpVPN+T
QqQdIkoFqvwbf8qQKhvTRPv/aYrE2+XXHbw760CFVdIZe3ypBHMj5QAALQHJq+Y+
eJeFDElGgP76uOks+IyFajoHZF8CB4NXNttwCveVGTCYT4tenbz5hEcCZWWljjfP
v3PBUcYJUnZOhruXeP8RGPL8zd3MCVQU1ltJwEliMV3ZyO2A1xSw+P9wvxqNXVx7
MqaFC+RmffDCd3KXAGda1PTjeeYiZFfb7wL5BwJY9PLj0jvJzRSITFt2OSdgI7sV
8CoqwdSzv0ATiHmMUjZzclRdxBArFO/3cjhSCjCGuydWET7j4IU7cgUpChpuZrr7
W/xsikw+yjHjeoXD3Wc3tlf5DjVm4kkeJzA3EC2OcB9Wq8dpzlI1leYslaBQPE2m
5wIDAQABo4IBODCCATQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQIXxvI
cuyENn/K94Y87LP1OJk93DAXBgNVHSAEEDAOMAwGCisGAQQBoXoCAgEwgbcGA1Ud
HwSBrzCBrDCBqaBHoEWGQ2h0dHA6Ly9jcmwucGhvZW5peGNvbnRhY3QuY29tL2Rl
dmljZXBraS9SU0FQaG9lbml4Q29udGFjdFJvb3RDQS5jcmyiXqRcMFoxIzAhBgNV
BAMMGlJTQSBQaG9lbml4IENvbnRhY3QgUm9vdENBMSYwJAYDVQQKDB1QaG9lbml4
IENvbnRhY3QgR21iSCAmIENvLiBLRzELMAkGA1UEBhMCREUwHQYDVR0OBBYEFAhf
G8hy7IQ2f8r3hjzss/U4mT3cMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF
AAOCAgEATvQdIU6YsyTllee4Hshl5u1WlwcW3U5sLeilaP1ByXYWQGUNnZEHZ+WI
rCmHqJnWe7W1jTRK5PHn4p4vFJ0YvBWyaApRrUOh/11x0cyrCyzqZ3qGD/gJLyN1
lBUmRVBMCpFJnQnvkPoEP1ExL6x/rtw654V7SqIsGGmtRurFgX8JBO9CV8DytHT6
HGWkkO02eK5BquLyFfTG6fmO4aKMH5EOzWZY71c/TCnbhLrvIEVSeKCC+FgybSCp
gs4O1t0Om2cC4pQeeynUoFv0BeKFKQUL4uH/xtupugsteYEeVDJ88IAIulJ23LyK
f9GOZNhUwSbwMfp7HE5JOACReHiwtRFU4uPFHc2CkkPOxKVg3Do2Cv8JsyTWGQ1b
/J9AHqbEK2OpM74MDLlP3jMbYqpY4yuZ0dlWewOKACyVNl+86GsYqs9g4MPpqA62
eHgXONSFubHvpsfdippBZRa2tV5k4/HWuuWih+PFr3ARluxc5gB7n8/t0mUzUGTb
tdBB0QWHM/jT2foDJwJmwXkq0P5YviYC7S5ZPp/JsN3lOe2QRswJFWPog+GWYG8r
15lAsGtOYRks2GOgPQ+78U3IVOFkRoN2Ljd8DURItwWXdKHo8NOdU0G+vPqewKnW
q3O9SQDS+iYTML0BoKcEZn7CuuJZsRVkoXBr/kEvzf0cWWPdpKc=
-----END CERTIFICATE-----
"""
ca_cert = load_pem_x509_certificate(ca_cert_pem.encode())

# Create CA validations
validation = CompositeValidation(is_ca=False)
validation.add_validation(SerialNumberValidation())
validation.add_validation(SignatureValidation())
validation.add_validation(IssuerValidation())
validation.add_validation(
    ValidityValidation(
        not_before=datetime(2023, 1, 1, tzinfo=timezone.utc), not_after=datetime(2030, 12, 31, tzinfo=timezone.utc)
    )
)
validation.add_validation(SubjectValidation())
validation.add_validation(SubjectPublicKeyInfoValidation())
validation.add_validation(UniqueIdentifiersValidation())
validation.add_validation(AuthorityKeyIdentifierValidation())
validation.add_validation(SubjectKeyIdentifierValidation())
validation.add_validation(KeyUsageValidation())
validation.add_validation(CertificatePoliciesValidation())
validation.add_validation(SubjectAlternativeNameValidation())
validation.add_validation(IssuerAlternativeNameValidation())
validation.add_validation(SubjectDirectoryAttributesValidation())
validation.add_validation(BasicConstraintsValidation())
validation.add_validation(NameConstraintsValidation())
validation.add_validation(PolicyConstraintsValidation())
validation.add_validation(ExtendedKeyUsageValidation())
validation.add_validation(CRLDistributionPointsValidation())
validation.add_validation(InhibitAnyPolicyValidation())
validation.add_validation(FreshestCRLValidation())


validation.add_validation(
    SubjectAttributesValidation(
        required={'2.5.4.3': [re.compile(r'(?i)^san_tst_.*$')], '2.5.4.11': [re.compile(r'^Open Industrial PKI$')]},
        optional={'2.5.4.10': [re.compile(r'(?i)^trustpoint_o_.*$')]},
    )
)

san_validation = SANAttributesValidation(
    required={
        'dNSName': [re.compile(r'(?i)^example.*$')],  # Regex for DNS names starting with 'example' (case-insensitive)
        'IPAddress': [re.compile(r'^192\.168\.0\.1$'), re.compile(r'^2001:db8:85a3::8a2e:370:7334$')],
    },
    optional={
        'uniformResourceIdentifier': [
            re.compile(r'^http://example\.com$'),
            re.compile(r'^https://example\.com/resource$'),
        ]
    },
)


# Perform validation
is_valid_ca = validation.validate(ca_cert)
print('Certificate validation result:', is_valid_ca)
print('Errors:', validation.get_errors())
print('Warnings:', validation.get_warnings())
