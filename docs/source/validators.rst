Validators
==========

This section describes the validator classes that are meant to validate both the structure (chain) and usage of
PKI objects like IssuingCas, TrustStores and X509 Credentials.

This uses the composite pattern to be very flexible on the validations corresponding to the different
objects we have to consider like Issuing CAs, Trust-Stores, CRLs, ...


Enums
-----

.. uml::
    :align: center

    enum CertificateValidationErrorsAndWarnings

Composite Pattern and Validators
--------------------------------

In this composite implementation, the leaf only differs from a composite by having an empty child_validators list.
It would become a composite as soon as a further validator is added to its list.
Thus, in practice, we will only have ValidatorComponents and do not differentiate between the leaf and composite.

error and warning will return the current error or warning, if any. errors and warnings will return a list of all
errors and warnings occurred within the children.

In most cases it is intended that the content of error, if any, is displayed as django ValidationError and thus displayed
within the form.

All other occurred errors and warnings shall be displayed in a separate detail error view which is opened on
user interaction only.

.. uml::
    :align: center

    abstract class ValidatorComponent {
        +error : CertificateValidationErrorsAndWarnings
        +errors : list[CertificateValidationErrorsAndWarnings]
        +warning : CertificateValidationErrorsAndWarnings
        +warnings : list[CertificateValidationErrorsAndWarnings]
        -child_validators : list[ValidatorComponent]
        --
        +validate(**kwargs) : bool {abstract}
        +add_validator(validator : ValidatorComponent) : void
        +remove_validator(validator : ValidatorComponent) : void
    }
    abstract class ValidatorLeaf
    abstract class ValidatorComposite

    ValidatorComponent <|-- ValidatorLeaf
    ValidatorComponent <|-- ValidatorComposite

    ValidatorComponent --o ValidatorComposite


Standard Validators
-------------------

This sections describes some standard validators which are used to validate common objects, like local Issuing CAs or
x509 Credentials. This also includes further common restriction, e.g. that an Issuing CA must
not only be allowed to issue new certificates, but also be allowed to sign CRLs (KeyUsage Extension).

Certificate Validators
~~~~~~~~~~~~~~~~~~~~~~

These validators validate a single certificate only. They do not consider certificate chains or corresponding keys.

Certificate Base Validators
...........................

.. uml::
    :align: center

    abstract class ValidatorComponent
    abstract class CertificateBaseValidator {
        --
        validate(certificate : x509.Certificate, **kwargs)
    }

    ValidatorComponent <|-- CertificateBaseValidator

    class CertificateValidator
    class EndEntityCertificateValidator
    class CaCertificateValidator

    CertificateBaseValidator <|-- CertificateValidator
    CertificateBaseValidator <|-- EndEntityCertificateValidator
    CertificateBaseValidator <|-- CaCertificateValidator

    EndEntityCertificateValidator --o CertificateValidator
    CaCertificateValidator --o CertificateValidator

End-Entity Certificate Validators
.................................

.. uml::
    :align: center

    abstract class CertificateBaseValidator
    class EndEntityCertificateValidator
    class TlsServerCertificateValidator
    class TlsClientCertificateValidator
    class IeeeIDevIdCertificateValidator
    class IeeeLDevIdCertificateValidator

    EndEntityCertificateValidator o-- TlsServerCertificateValidator
    EndEntityCertificateValidator o-- TlsClientCertificateValidator
    EndEntityCertificateValidator o-- IeeeIDevIdCertificateValidator
    EndEntityCertificateValidator o-- IeeeLDevIdCertificateValidator

    CertificateBaseValidator <|-- EndEntityCertificateValidator
    CertificateBaseValidator <|-- TlsServerCertificateValidator
    CertificateBaseValidator <|-- TlsClientCertificateValidator
    CertificateBaseValidator <|-- IeeeIDevIdCertificateValidator
    CertificateBaseValidator <|-- IeeeLDevIdCertificateValidator


CA Certificate Validators
.........................

.. uml::
    :align: center

    abstract class CertificateBaseValidator
    class CaCertificateValidator
    class IssuingCaCertificateValidator
    class RootCaCertificateValidator

    CertificateBaseValidator <|-- CaCertificateValidator
    CertificateBaseValidator <|-- IssuingCaCertificateValidator
    CertificateBaseValidator <|-- RootCaCertificateValidator

    IssuingCaCertificateValidator --o CaCertificateValidator
    RootCaCertificateValidator --o CaCertificateValidator


Certificate Chain Validators
----------------------------

TODO

Private Key Validators
----------------------

TODO, e.g. weak keys and algorithms

Certificate and Private Key Match Validators
--------------------------------------------

TODO, validates that the private key matches the public key in the certificate


Factory Method Pattern
----------------------

We use a factory pattern to instantiate these validator classes.

.. uml::
    :align: center

    class CertificateValidatorFactory {
        --
        create_validator() : CertificateValidator
    }

    class EndEntityCertificateValidatorFactory {
        --
        create_validator() : EndEntityCertificateValidator
    }

    class CaCertificateValidatorFactory {
        --
        create_validator() : CaCertificateValidator
    }

    class TlsServerCertificateValidatorFactory {
        --
        create_validator() : TlsServerCertificateValidator
    }

    class TlsClientCertificateValidatorFactory {
        --
        create_validator() : TlsClientCertificateValidator
    }

    class IssuingCaCertificateValidatorFactory {
        --
        create_validator() : IssuingCaCertificateValidator
    }

    class RootCaCertificateValidatorFactory {
        --
        create_validator() : RootCaCertificateValidatorFactory
    }

    CertificateValidatorFactory <|-- EndEntityCertificateValidatorFactory
    CertificateValidatorFactory <|-- CaCertificateValidatorFactory

    EndEntityCertificateValidatorFactory <|-- TlsServerCertificateValidatorFactory
    EndEntityCertificateValidatorFactory <|-- TlsClientCertificateValidatorFactory

    CaCertificateValidatorFactory <|-- IssuingCaCertificateValidatorFactory
    CaCertificateValidatorFactory <|-- RootCaCertificateValidatorFactory
