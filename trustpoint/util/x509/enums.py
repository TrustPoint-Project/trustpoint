from __future__ import annotations
from enum import Enum


class TpEnum(Enum):

    def __new__(cls, value, pretty_name):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.pretty_name = pretty_name
        return obj


class Version(TpEnum):

    V1 = (0, 'Version 1')
    V2 = (1, 'Version 2')
    V3 = (2, 'Version 3')

    def __str__(self) -> str:
        return str(self.value)


class SignatureAlgorithmOid(TpEnum):

    RSA_WITH_MD5 = ('1.2.840.113549.1.1.4', 'MD5 with RSA')
    RSA_WITH_SHA1 = ('1.2.840.113549.1.1.5', 'SHA1 with RSA')
    _RSA_WITH_SHA1 = ('1.3.14.3.2.29', 'SHA1 with RSA')
    RSA_WITH_SHA224 = ('1.2.840.113549.1.1.14', 'SHA224 with RSA')
    RSA_WITH_SHA256 = ('1.2.840.113549.1.1.11', 'SHA256 with RSA')
    RSA_WITH_SHA384 = ('1.2.840.113549.1.1.12', 'SHA384 with RSA')
    RSA_WITH_SHA512 = ('1.2.840.113549.1.1.13', 'SHA512 with RSA')
    RSASSA_PSS = ('1.2.840.113549.1.1.10', 'PSS with RSA')
    ECDSA_WITH_SHA1 = ('1.2.840.10045.4.1', 'ECDSA with SHA1')
    ECDSA_WITH_SHA224 = ('1.2.840.10045.4.3.1', 'ECDSA with SHA224')
    ECDSA_WITH_SHA256 = ('1.2.840.10045.4.3.2', 'ECDSA with SHA256')
    ECDSA_WITH_SHA384 = ('1.2.840.10045.4.3.3', 'ECDSA with SHA384')
    ECDSA_WITH_SHA512 = ('1.2.840.10045.4.3.4', 'ECDSA with SHA512')

    def __str__(self) -> str:
        return str(self.value)


if __name__ == '__main__':
    v = Version.V3
    print(v)
    print(v.value)
