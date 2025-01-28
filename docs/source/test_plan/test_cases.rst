Since we are using the `BDD <https://cucumber.io/docs/bdd/>`_ principle for system and integration testing,
we decided on specifying the tests directly inside the `Cucumber <https://cucumber.io/>`_ feature files.
This has the advantage of removing the need to keep two or more documents updated at the same time.
Also, `Gherkin <https://cucumber.io/docs/gherkin/>`_ is a well organized language such that the test ideas and steps
are possible to read - even for people without a background in software engineering.
That being said, we state the feature files in the following and provide a brief description on the test ideas.

^^^^^
R_001
^^^^^

This testcase is related to requirement `R_001`_.

"""""""""
Test Idea
"""""""""

To test the requirement of creating, viewing, editing, and deleting digital identities using the TPC_Web interface,
the focus will be on validating the complete lifecycle of identity management through the web platform.

The test would start with an admin user creating a new digital identity through the web interface.
This process involves navigating to the appropriate page, filling out the required fields (e.g., name and identifier),
and submitting the form. Once the identity is created,
the test would verify that it appears in the list of identities and that all details are accurately displayed on its details page.

Following the creation, the admin user would edit the identity's details,
such as updating the name or identifier, and save the changes.
The test should confirm that the modifications are reflected immediately and correctly in both the details view and any listings.

Finally, the test would validate the deletion process,
where the admin removes the identity through the web interface.
Once deleted, the system should ensure that the identity is no longer accessible or visible in any lists or details pages.
Additional negative tests could confirm appropriate handling when attempting to access or manipulate a non-existent or already-deleted identity.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_001_CRUD.feature
   :language: gherkin

^^^^^
R_002
^^^^^

This testcase is related to requirement `R_002`_.

"""""""""
Test Idea
"""""""""

""""""""""""
Feature File
""""""""""""

^^^^^
R_003
^^^^^

This testcase is related to requirement `R_003`_.

"""""""""
Test Idea
"""""""""

To test the complete lifecycle management of certificates,
the focus will be on ensuring that admin users can successfully perform actions such as renewing and revoking certificates via the TPC_Web interface.

The test begins by identifying an existing certificate.
Using TPC_Web, the admin initiates the renewal process,
and the system updates the expiration date.
Similarly, the admin navigates to the certificate management page and initiates a revocation process.
The system should confirm the action and reflect the certificate's updated status as revoked.

Edge cases include attempting to renew or revoke non-existent certificates or
performing actions on certificates in invalid states (e.g., already revoked certificates).
The system should handle these scenarios gracefully, with appropriate error messages or restrictions.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_003_certificate_lifecycle.feature
   :language: gherkin

^^^^^
R_004
^^^^^

This testcase is related to requirement `R_004`_.

"""""""""
Test Idea
"""""""""

To test the REST API for interacting with TrustPoint programmatically,
we focus on verifying CRUD operations (Create, Read, Update, Delete) and additional actions like querying and filtering.
We begin by validating that authorized API clients can authenticate successfully and perform each operation on digital identities.
This includes creating a new identity,
retrieving its details, updating its attributes, and deleting it.
Each API response should include appropriate status codes and payloads.

Error handling should also be tested, such as attempting operations with invalid data,
unauthorized access, or on non-existent resources.
Edge cases, such as rate limits or concurrent requests, should be addressed to confirm robustness.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/R_004_REST_API.feature
   :language: gherkin