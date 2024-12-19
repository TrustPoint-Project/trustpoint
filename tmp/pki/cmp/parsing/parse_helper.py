from cryptography.hazmat.primitives import hashes


class ParseHelper:
    """
    A class to handle several objects for parsing.

    Attributes:
        REASON_CODES (dict): Mapping of reason code integers to their string descriptions.
        OID_TO_NAME (dict): Mapping of OIDs to attribute names.
        PKI_STATUSES (dict): Mapping of PKI statuses to their integer codes.
        oid_to_hash (dict): A dictionary mapping OIDs to hash functions.
    """

    REASON_CODES = {
            0: 'unspecified',
            1: 'keyCompromise',
            2: 'cACompromise',
            3: 'affiliationChanged',
            4: 'superseded',
            5: 'cessationOfOperation',
            6: 'certificateHold',
            8: 'removeFromCRL',
            9: 'privilegeWithdrawn',
            10: 'aACompromise'
        }

    OID_TO_NAME = {
        '2.5.4.3': 'CN',
        '2.5.4.10': 'O',
        '2.5.4.11': 'OU',
        '2.5.4.6': 'C',
        '2.5.4.7': 'L',
        '2.5.4.8': 'ST',
        '2.5.4.9': 'STREET',
        '2.5.4.4': 'SN',
        '2.5.4.42': 'GIVENNAME',
        '1.2.840.113549.1.9.1': 'EMAIL'
    }

    PKI_STATUSES = {
        'accepted': 0,
        'grantedWithMods': 1,
        'rejection': 2,
        'waiting': 3,
        'revocationWarning': 4,
        'revocationNotification': 5,
        'keyUpdateWarning': 6
    }

    oid_to_hash = {
        '1.2.840.113549.1.1.11': hashes.SHA256,
        '1.2.840.113549.1.1.12': hashes.SHA384,
        '1.2.840.113549.1.1.13': hashes.SHA512,
        '1.3.6.1.5.5.8.1.2': hashes.SHA1,
        '2.16.840.1.101.3.4.2.1': hashes.SHA256,
        '2.16.840.1.101.3.4.2.2': hashes.SHA384,
        '2.16.840.1.101.3.4.2.3': hashes.SHA512
    }

    oid_to_protection_type = {
        '1.2.840.10045.4.3.2': 'ECDSA with SHA256',
        '1.2.840.113549.1.1.5': 'RSA with SHA-1',
        '1.2.840.113549.1.1.11': 'RSA with SHA-256',
        '1.2.840.113549.1.1.12': 'RSA with SHA-384',
        '1.2.840.113549.1.1.13': 'RSA with SHA-512',
        '1.2.840.113533.7.66.13': 'Password-based MAC'
    }

