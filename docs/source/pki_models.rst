PKI Application Models
======================

Overview
--------

.. uml::
    :align: center

    class CertificateModel
    class IssuingCaModel
    class TrustStoreModel
    class CrlModel
    class X509CredentialModel

    CertificateModel o-- IssuingCaModel
    CertificateModel o-- TrustStoreModel
    CertificateModel o-- CrlModel
    CertificateModel o-- X509CredentialModel

Certificate Model
-----------------
This model must only be used for reading.
Saving certificates in the database must only be invoked by the following objects:

- IssuingCAInitializer
- TrustStoreInitializer
- CredentialInitializer

.. uml::
    :align: center

    enum CertificateStatus {
        +OK
        +REVOKED
        --
    }

    enum Version {
        +V3
        --
    }

    enum SignatureAlgorithmOid
    enum PublicKeyAlgorithmOid
    enum EllipticCurveOid

    class CertificateModel {
        +certificate_status : models.CharField (Enum CertificateStatus) {read only}
        +SignatureAlgorithmOidChoices : Enum SignatureAlgorithmOid {read only}
        +PublicKeyAlgorithmOidChoices : Enum PublicKeyAlgorithmOid {read only}
        +PublicKeyEcCurveOidChoices : Enum PublicKeyEcCurveOidChoices
        +common_name : models.CharField {read only}
        +sha256_fingerprint : models.CharField {read only}
        +signature_algorithm_oid : models.CharField {read only}
        +signature_algorithm : str {read only}
        +signature_algorithm_padding_scheme : str {read only}
        +signature_algorithm_padding_scheme : str {read only}
        +signature_value : models.CharField {read only}
        +version : models.PositiveSmallIntegerField (Enum Version) {read only}
        +serial_number : models.CharField {read only}
        +issuer : models.ForeignKey
        +issuer_public_bytes : models.CharField {read only}
        +not_valid_before : models.DateTimeField {read only}
        +not_valid_after : models.DateTimeField {read only}
        +subject : models.ManyToManyField {read only}
        +subject_public_bytes : models.CharField {read only}
        +spki_algorithm_oid : models.CharField {read only}
        +spki_algorithm : models.CharField {read only}
        +spki_key_size : models.PositiveIntegerField {read only}
        +spki_ec_curve_oid : models.CharField {read only}
        +spki_ec_curve : models.CharField {read only}
        +cert_pem : models.CharField {read only}
        +public_key_pem : models.CharField {read only}
        +private_key_pem : None | models.CharField {read only}
        --
        +get_cert_as_pem() : bytes
        +get_cert_as_der() : bytes
        +get_cert_as_crypto() : x509.Certificate
        +get_public_key_as_pem() : str
        +get_public_key_as_der() : bytes
        +get_public_key_as_crypto() : rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    }

    CertificateModel --o CertificateStatus
    CertificateModel --o Version
    CertificateModel --o SignatureAlgorithmOid
    CertificateModel --o PublicKeyAlgorithmOid
    CertificateModel --o EllipticCurveOid


Issuing CA Model
----------------

.. uml::
    :align: center

    class IssuingCaModel {
        +root_ca_cert : ForeignKey (CertificateModel)
        +intermediate_ca_certs : ManyToManyField (CertificateModel : order - through)
        +issuing_ca_cert : ForeignKey (CertificateModel)
        +private_key : bytes | None (DER Format)
        +pkcs11_private_key_access : ForeignKey(Pkcs11PrivateKeyAccess)
        +remote_ca_config : ForeignKey(RemoteCaConfig)
        --
        +get_issuing_ca() : IssuingCa
        +get_cert_chain() : list[CertificateModel]
        +get_cert_chain_as_pem() : list[bytes]
        +get_cert_chain_as_crypto() : list[x509.Certificate]
    }

DB constraints
~~~~~~~~~~~~~~

Exactly one of the following must be set (at least one & at most one)

- private_key
- pkcs11_private_key_access
- remote_ca_config

Depending on which field is set, the method get_issuing_ca() will create and return a different IssuingCa object
which will allow to issue new certificates and sign CRLs, thus providing an abstraction layer for issuing certificates.

The user / developer does not have to be concerned about the type (local, remote, ...) of the Issuing CA.

TrustStore Model
----------------

.. uml::
    :align: center


    class TrustStoreModel {
        +certificates : ManyToManyField (CertificateModel : order - through)
        --
        +get_trust_store() : TrustStore
        +get_trust_store_as_pem() : list[bytes]
        +get_trust_store_as_crypto() : list[x509.Certificate]
    }


CRL Model
---------

.. uml::
    :align: center

    class CrlModel

X509 Credential Model
---------------------

.. uml::
    :align: center

    class X509CredentialModel