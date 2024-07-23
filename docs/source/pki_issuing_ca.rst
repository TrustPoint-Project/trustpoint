Issuing CA Objects
==================

Issuing CA Initializers
-----------------------

Initializers are responsible to validate and store new Issuing CAs.
These are only utilized once on creation and storage in the DB of new Issuing CAs.

These initializers are meant to be the ONLY way to create and store a new Issuing CA within the system.

.. uml::
    :align: center

    abstract class IssuingCaInitializer
    abstract class RemoteCaEndpoint
    abstract class ApiCredential

    class IssuingCaFileSerializer
    class IssuingCaValidator

    class LocalIssuingCaFromRemoteCaInitializer
    class RemoteIssuingCaInitializer
    class RemoteCaEstEndpoint
    class RemoteCaCmpEndpoint


    IssuingCaInitializer <|.. LocalIssuingCaFromFileInitializer
    LocalIssuingCaFromFileInitializer --o IssuingCaFileSerializer
    LocalIssuingCaFromFileInitializer --o IssuingCaValidator

    IssuingCaInitializer <|.. LocalIssuingCaFromRemoteCaInitializer
    IssuingCaInitializer <|.. RemoteIssuingCaInitializer

    LocalIssuingCaFromRemoteCaInitializer --o RemoteCaEndpoint
    RemoteIssuingCaInitializer --o RemoteCaEndpoint
    RemoteCaEndpoint o-- ApiCredential

    RemoteCaEndpoint <|.. RemoteCaEstEndpoint
    RemoteCaEndpoint <|.. RemoteCaCmpEndpoint


Issuing CA Objects
------------------

These objects are meant to be utilized when using Issuing CAs to actually issue certificates or (sign) CRLs.

.. uml::
    :align: center

    abstract class IssuingCa {
        -_validator : Validator
        -_IssuingCaFileSerializer : IssuingCaFileSerializer
        +unique_name : str
        --
        +issue_certificate() : CertificateModel {abstract}
        +sign_crl() : CrlModel {abstract}
        +get_issuing_ca_certificate_model() : CertificateModel
        +get_issuing_ca_certificate_as_pem() : bytes
        +get_issuing_ca_certificate_as_der() : bytes
        +get_issuing_ca_certificate_as_crypto() : x509.Certificate
        +get_cert_chain() : list[CertificateModel]
        +get_cert_chain_as_pem() : list[bytes]
        +get_cert_chain_as_pkcs7() : bytes
        +get_cert_chain_as_crypto() : list[x509.Certificate]
    }

    class UnprotectedLocalIssuingCa {
        --
        +issue_certificate() : CertificateModel
        +sign_crl() : CrlModel
    }

    class Pkcs11LocalIssuingCa {
        --
        +issue_certificate() : CertificateModel
        +sign_crl() : CrlModel
    }

    class RemoteIssuingCa {
        --
        +issue_certificate() : CertificateModel
        +sign_crl() : CrlModel
    }

    IssuingCa <|.. UnprotectedLocalIssuingCa
    IssuingCa <|.. Pkcs11LocalIssuingCa
    IssuingCa <|.. RemoteIssuingCa