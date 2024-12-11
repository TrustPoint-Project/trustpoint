import enum


class ProtectionAlgorithmOid(enum.Enum):

    PASSWORD_BASED_MAC = '1.2.840.113533.7.66.13'


class HashAlgorithmOid(enum.Enum):

    SHA256 = '2.16.840.1.101.3.4.2.1'


class MacOid(enum.Enum):

    HMAC_SHA1 = '1.3.6.1.5.5.8.1.2'


class CmpMessageType(enum.Enum):

    IR = 'ir'
    IP = 'ip'
    CR = 'cr'
    CP = 'cp'
