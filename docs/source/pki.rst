Software Architecture
=====================


Serializer
----------

Serializers konvert between ASN.1 objects and bytes, strings and similar formats.
We do want to have the code of these conversions in a central place, thus the serializer classes.

- CertificateSerializer
- IssuingCaSerializer
- TrustStoreSerializer
- CredentialSerializer


<type>Model
-----------

These describe the DB schemata for various PKI objects like IssuingCas, TrustStores, Credentials, CRLs, ...

These model classes shall only be used for read, edit (if possible for a field), searching, displaying in the
front-end, .... They shall not be used directly for performing actions like issuing a new certificate,
singing crls. For this the <type> objects are the appropriate abstraction.

<type>
------

Provide a generic way to use PKI objects corresponding to their type. E.g. an issuing ca could be saved in a way
so that the private key is directly in the db or it is saved and protected within an HSM. It could also be
a remote CA, so that the Trustpoint has to make a request to the remote CA. Concrete implementations of the abstract IssuingCa
class allow to abstract all this information away, so we can just use issue_certificate() or sign_crl(). We
do not have to know which type of Issuing CA it is.


Validator
---------

We need to validate different types of ASN.1 and PKI objects like IssuingCas, TrustStores, Credentials
(e.g. TlsClientCredential, IeeeIDevIdCredential, ...). To structure these validators and be able to reuse the code,
validators use the composite pattern.

Initializer
-----------

Since there are parsing, validation, conversions and multiple model classes (db schemata) involved, it can be quite
complex in regards to ASN.1 and PKI objects, it is not possible to directly save data on the
model using the save() method. It is instead abstracted into Initializer classes.

Initializer classes are intended to provide a simple API to create new PKI objects like IssuingCas, TrustStores and
Credentials. They are only used on creation, not on read, delete or modify.
