import re

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
     PolicyMappingsValidation,
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
from cryptography.x509 import load_pem_x509_certificate

ca_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIEuTCCAqGgAwIBAgIUZYZm+AG4647l3KneJv10i4OFrIIwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUT2lQS0ktc3ViLVRsc0NlcnQtQ0EwHhcNMjQxMjIwMTE1
MzE1WhcNMjYxMjIwMTE1MzE0WjAzMRMwEQYDVQQDDApzYW5fdGVzdF8xMRwwGgYD
VQQLDBNPcGVuIGluZHVzdHJpYWwgUEtJMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAvBohirZ3OtzC8I3I+bHLnJ3qHAaJ3bddPyTl4JS/V93WRHxfTm8B
Jt/ZsSK4rMSFmGDpsizoGdiDOAM+3Wbw/67fQmM0sTaAZ9vFVkpnD2lui/QKj6af
02ULS2TozSCvSvFS/z0JaBm4SaGZaFrkypNjgqYMXOLQaJbU2Er7UvNtEHsLdG6M
Vhq1mbOXvfyyBOym5XykiYxQqfzrJET+R9dJJ2ELzri2SWCREb39o6t+Nq9FYL1T
KtwgXF6yv+fDa2JRvfslkfnkMR3d2oPUp5BSvAG6kgU/Vy+/RncylYIz+FhUgp0q
+T4Gmzzhd3aUbD8AL3Fa9wUPSWlBTv49TQIDAQABo4HYMIHVMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAUeLXBduXss6aEG/QVV7kVsUjL/G8wYAYDVR0RBFkwV4IL
ZXhhbXBsZS5jb22HBMCoAAGHECABDbiFowAAAACKLgNwczSGEmh0dHA6Ly9leGFt
cGxlLmNvbYYcaHR0cHM6Ly9leGFtcGxlLmNvbS9yZXNvdXJjZTATBgNVHSUEDDAK
BggrBgEFBQcDATAdBgNVHQ4EFgQUndMbmx9L3fzSHF0So+7NTADpH+QwDgYDVR0P
AQH/BAQDAgXgMA0GCSqGSIb3DQEBCwUAA4ICAQBeWos1M4N4TDZ+uSofFx/DC0q4
1F8xMSL6Sv82sQo5AsoKrgQvyZbpOVVwv3KKGdm+G6M87H/Fm3zADDb8g9JV+iLq
nzUbbhH3WwbDRImS17896yF5pHgDPNNxVYuT5L9AU8233E719O5xYeEoUwCZxloV
ePPhmO0dKkCxeljP25i85YWdr1rHw4SZDqhF+5bLEOR9boviPmhvDs1PNcBLIyzq
tSq1qPxKrtH3q9AKxCaj8TjRI3T8PQ897YnAZ5ufEj+Z57lMa8QHdWGLIxHIr02X
VcvPDwPPYiSsHt4d1Mtmz3yxhJYH73yjUkFC6aRMl4kty1zyVRjR70weQ0SOtbR5
3tAeu+bcfVNFzWtc5T2pqtx7Uktbei6O1f3hfZdAD2fh81nwuFd00DwNnasvTlUP
TXGJ3z/BT3bKYt4e0aWCMqlmbt3/t6TLaPImubGpoLZyWj+DCi/sztFF9Kr6HZpp
DFKtxx40L2fyBT9dP6GYk73rLRlbJNDU1xwqHqneEd+Satv4VrbncLSMMgnymUpG
wo/l16v4jrUKJvRWUbCpqAPSieAPcT5VH7g+8h9dMjwTXbwzvsGfpuALY+bSN1dF
xtAFOeoMrWOhv/Yr3MGzaZNRV5Fyrg/48g8KOnTlIOigDabOWNP1zQR7ev8LLV28
9KgUboaKYLvvxb7Jog==
-----END CERTIFICATE-----
"""
ca_cert = load_pem_x509_certificate(ca_cert_pem.encode())

# Create CA validations
validation = CompositeValidation(is_ca=False)
validation.add_validation(SerialNumberValidation())
validation.add_validation(SignatureValidation())
validation.add_validation(IssuerValidation())
validation.add_validation(ValidityValidation())
validation.add_validation(SubjectValidation())
validation.add_validation(SubjectPublicKeyInfoValidation())
validation.add_validation(UniqueIdentifiersValidation())
validation.add_validation(AuthorityKeyIdentifierValidation())
validation.add_validation(SubjectKeyIdentifierValidation())
validation.add_validation(KeyUsageValidation())
validation.add_validation(CertificatePoliciesValidation())
validation.add_validation(PolicyMappingsValidation())
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


validation.add_validation(SubjectAttributesValidation(
     required={'2.5.4.3': [re.compile(r'(?i)^san_test_.*$')],
               '2.5.4.11': ['Open industrial PKI']},
     optional={'2.5.4.10': [re.compile(r'(?i)^trustpoint_o_.*$')]}
 ))

validation.add_validation(SANAttributesValidation(
    required={'dNSName': [re.compile(r'(?i)^example.*$')],
              'IPAddress': ['192.168.0.1', '2001:db8:85a3::8a2e:370:7334']},
    optional={'uniformResourceIdentifier': ['http://example.com', 'https://example.com/resource']}
))

# Perform validation
is_valid_ca = validation.validate(ca_cert)
print('Certificate validation result:', is_valid_ca)
print('Errors:', validation.get_errors())
print('Warnings:', validation.get_warnings())
