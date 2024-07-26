Serializers
===========

.. uml::
    :align: center

    abstract class Serializer

    class CertificateSerializer {
        -_certificate : x509.Certificate
        --
        +__init__(certificate : x509.Certificate) : None
        +from_bytes(certificate : bytes) : CertificateSerializer {classmethod}
        +from_string(certificate : str) : CertificateSerializer {classmethod}
        +get_as_pem() : bytes
        +get_as_der() : bytes
        +get_as_crypto() : x509.Certificate
        -_load_pem_certificate(certificate : bytes) : x509.Certificate
        -_load_der_certificate(certificate : bytes) : x509.Certificate
    }

    Serializer <|-- CertificateSerializer


.. uml::
    :align: center

    abstract class Serializer

    class PublicKeySerializer {
        -_public_key : PublicKey
        --
        +__init__(public_key : PublicKey) : None
        +from_bytes(public_key : bytes) : PublicKeySerializer {classmethod}
        +from_string(public_key : str) : PublicKeySerializer {classmethod}
        +get_as_pem() : bytes
        +get_as_der() : bytes
        +get_as_crypto() : PublicKey
        -_load_pem_public_key(public_key : bytes) : PublicKey
        -_load_der_public_key(public_key : bytes) : PublicKey
    }

    Serializer <|-- PublicKeySerializer


.. uml::
    :align: center

    abstract class Serializer

    class CertificateChainSerializer {
        -_public_key : PublicKey
        --
        +__init__(certificate_chain : list[x509.Certificate]) : None
        +from_bytes(certificate_chain : bytes) : CertificateChainSerializer {classmethod}
        +from_list_of_bytes(certificate_chain : list[bytes]) : CertificateChainSerializer {classmethod}
        +from_string(certificate_chain : str) : CertificateChainSerializer {classmethod}
        +from_list_of_strings(certificate_chain : list[str]) : CertificateChainSerializer {classmethod}
        +get_as_pem() : bytes
        +get_as_pem_pkcs7() : bytes
        +get_as_der_pkcs7() : PublicKey
        +get_as_crypto() : list[x509.Certificate]
        -_load_pem_certificate(certificate : bytes) : x509.Certificate
        -_load_der_certificate(certificate : bytes) : x509.Certificate
    }

    Serializer <|-- CertificateChainSerializer