Trustpoint Architecture
=======================

General Overview
----------------

.. image:: _static/trustpoint-architecture.drawio.svg
    :align: center

The Domain and Issuing CA generally have a one to one relationship (unless there is an active rollover process active).

The Issuing CA abstractions allows to configure different types of CAs. These may be either local or remote CAs.

The Domain abstractions allows to configure the endpoint for the devices including different types of PKI protocols like
EST, CMP and REST including CRL distribution, OCSP endpoint and further Trust Stores.

