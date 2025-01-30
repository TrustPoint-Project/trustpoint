^^^^^
R_101
^^^^^

This testcase is related to requirement `R_101`_.

"""""""""
Test Idea
"""""""""

To verify that only devices with valid certificates can communicate, we will test the following scenarios:

#. Device with a Valid Certificate Can Communicate
    - A device is provisioned with a valid certificate.
    - The system allows the device to establish communication.

#. Device with an Expired Certificate is Denied
    - A device presents an expired certificate.
    - The system denies communication and logs the attempt.

#. Device with a Revoked Certificate is Denied
    - A certificate is revoked by the system administrator.
    - A device attempting to communicate with the revoked certificate is rejected.

#. Device with a Self-Signed or Untrusted Certificate is Denied
    - A device presents a self-signed certificate.
    - The system denies communication.

#. Device with a Tampered Certificate is Denied
    - A device presents a certificate with altered data.
    - The system detects the tampering and blocks communication.

#. Device Attempts Communication Without a Certificate
    - A device attempts to communicate without presenting any certificate.
    - The system rejects the request.

#. Logging of Authentication Failures
    - Every failed authentication attempt due to an invalid, expired, or revoked certificate is logged.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_001_CRUD.feature
   :language: gherkin