=========
Test Plan
=========

This document is providing a test plan for TrustPoint using the IEEE 829 standard for structuring this plan.


------------
Introduction
------------

The purpose of this test plan should be to test all required functions which are briefly described
inside the `GitHub repository <https://github.com/TrustPoint-Project/trustpoint>`_.
Also, there is a separation between functionality and user experience.
Since the project is heavily relying on securing networks as simple as possible,
the user experience should be as important as the functionality.

Summarized, this test plan is intended to ensure, through the execution and documentation of all tests, the

- functionality,
- usability,
- security and
- integration capability

of TrustPoint.
This is done by specifying and implementing the above-mentioned requirements in software tests.


----------------------
Test Items (Functions)
----------------------

This chapter lists all needed requirements of TrustPoint, e.g. creating certificates.
These requirements are only back-end requirements.

^^^^^^
Actors
^^^^^^

First, we define all needed actors to be as specific as needed.

.. _TrustPoint-Actors-Table:

.. csv-table:: TrustPoint Actors
   :header: "ID", "Name", "Description"
   :widths: 10 30 60

   "TPC_CLI", "TrustPoint Core Command Line Interface", "The command line program of TrustPoint."
   "TPC_Web", "TrustPoint Core Web Interface", "The website of TrustPoint."
   "TP_Client", "TrustPoint Client", "The TrustPoint client program to be installed on clients."
   "Admin", "Admin", "The admin user of this specific TrustPoint environment."
   "NTEU", "Non-technically experienced user", "A user who is not necessarily technically experienced. This could also be an admin."
   "TEU", "Technically experienced user", "A user who does know at least a little bit about programming and PKI."

^^^^^^^^^^^^
Requirements
^^^^^^^^^^^^

Next, we list all requirements.
Note that this list could (and will be) incomplete.

"""""""""""""""""""""""
Functional Requirements
"""""""""""""""""""""""

.. csv-table:: Functional Requirements
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

   _`R_001`, "Create, view, edit and delete an identity", "TPC_CLI and TPC_Web must provide a way to create, view, edit and delete a digital identity.", "TPC_CLI, TPC_Web, Admin", "High"
   _`R_002`, "Manage an identity", "TPC_CLI and TPC_Web must be able to renew certificates.", "TPC_CLI, TPC_Web, Admin", "Medium"
   _`R_003`, "Usage of any zero touch onboarding protocol", "Any zero touch onboarding protocol should be used, preferably the Bootstrapping Remote Secure Key Infrastructure (BRSKI) process, while connecting a new device to the network.", "TPC_CLI, TP_Client", "High"
   _`R_004`, "Certificate Lifecycle Management", "Enable complete lifecycle management for certificates, including renewal and revocation.", "All components", "High"
   _`R_005`, "REST API", "Provide a REST API for interacting with TrustPoint programmatically.", "TPC_Web, TPC_CLI", "High"
   _`R_006`, "Docker Container Support", "Distribute TrustPoint within a fully-configured Docker container for deployment.", "TPC_CLI, TPC_Web", "Medium"
   _`R_007`, "Backup, Restore, and Update Mechanisms", "Implement backup, restoration, and update features to ensure data and system resilience.", "TPC_CLI, TPC_Web, Admin", "High"
   _`R_008`, "Logging Capabilities", "Provide detailed and configurable logging for system events and actions.", "TPC_CLI, TPC_Web, TP_Client", "High"
   _`R_009`, "Auto-Generated Issuing CAs", "Automatically generate Issuing Certificate Authorities based on configuration.", "TPC_CLI", "High"
   _`R_010`, "High Availability", "Ensure system availability using redundancy or failover mechanisms.", "TPC_CLI, TPC_Web, TP_Client", "High"
   _`R_011`, "CMP Endpoint for Onboarded Devices", "Provide a CMP endpoint for device onboarding.", "All components", "High"
   _`R_012`, "EST Endpoint for Onboarded Devices", "Provide an EST endpoint for device onboarding.", "All components", "High"
   _`R_013`, "Language Selection and Translation", "Support multi-language UI options for global usability.", "TPC_Web, TP_Client", "Medium"

"""""""""""""""""""""
Security Requirements
"""""""""""""""""""""

.. csv-table:: Security Requirements
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

   "R_101", "Devices are only allowed to communicate with valid certificates", "Machines or devices in the network are only allowed to communicate with a valid certificate.", "TP_Client (multiple)", "High"
   "R_102", "Encrypted Communication", "The communication between machines has to be encrypted with the given algorithm.", "TP_Client (multiple)", "High"
   "R_103", "Security Level Configuration", "Allow administrators to configure security levels for different TrustPoint components.", "Admin, TPC_CLI, TPC_Web", "Medium"
   "R_104", "Certificate Template Security", "Enforce access control and secure handling for certificate templates.", "TPC_CLI", "High"


--------------------
Software Risk Issues
--------------------

All software testing involves risks, which are listed below in order to minimize them.

- *Incomplete requirements:*
    As TrustPoint is a research project,
    it can happen that requirements are incomplete and only become apparent in retrospect that they would have been important.

- *Incomplete test coverage:*
    Although we strive to keep the test coverage as high as possible,
    sometimes not everything can be tested.
    As a result, some execution paths may be left out,
    with the resulting problems only becoming apparent during productive operation.

- *Lack of time for testing:*
    It could well happen that the test plan is too long and complex,
    so that we run out of time with the software tests.

- *Problems with the test environment:*
    Not every (automated) test can be carried out on a real environment.
    Therefore, simulation components are likely to be used,
    but these will probably not represent exactly the same devices as they will look like in the production environment.
    An example of this would be the simulation or integration of older machines which do not provide a certificate signed by the manufacturer.

- *User-friendliness:*
    The testers of the program's interface (acceptance testing) should be people with as little technical knowledge as possible,
    as otherwise the tests may give a false picture when tested by people from the development team.

- *Problems with manual testing:*
    We should thrive for automatic testing, although not every requirement can be tested automatically.
    That is, because the manual testing techniques are sometimes but not always the root of an error.


---------------------
Features To Be Tested
---------------------

This chapter lists all needed requirements of TrustPoint, e.g. creating certificates.
These requirements are now front-end requirements as well as user experience.
This is also the main difference between chapter `Test Items (Functions)`_ and this chapter.
The `table <TrustPoint-Actors-Table>`_ of all actors is still used though.

.. csv-table:: Features To Be Tested
   :header: "Name (Identifier)", "Title", "Description", "Component(s)", "Importance"
   :widths: 10, 25, 60, 30, 10

    "F_001", "NTEU must be able to execute R_001 and R_002.", "NTEU must be able to log in to the TCP_Web app and carry out the processes described in R_001 and R_002.  ", "TPC_CLI, TPC_Web, NTEU", "High"


-------------------------
Features Not To Be Tested
-------------------------

.. csv-table:: Features Not To Be Tested
   :header: "Feature (Description)", "Reason"
   :widths: 50, 50

    " ", " "

-------------------
Approach (Strategy)
-------------------

^^^^^^^^^^^^^^
Testing Levels
^^^^^^^^^^^^^^

The testing will consist of Unit, System/Integration (combined), and Acceptance test levels.

""""""""""""
Unit Testing
""""""""""""

Unit testing will be conducted by the developers and approved by another developer.
Before unit testing is considered complete and the components are passed on for further testing,
developers must provide evidence of successful testing. This includes:

- A list of test cases executed
- Sample output
- Input data sets
- Documentation of identified and resolved defects

Note that this can be done automatically.

All unit test artifacts will also be shared with the test engineer for validation and record-keeping.
The focus of unit testing will be on verifying the functionality of individual modules of TrustPoint.

""""""""""""""""""""""""""
System/Integration Testing
""""""""""""""""""""""""""

System/Integration testing will be carried out by the test developer and the full development team.
The primary goal at this stage is to ensure that all TrustPoint modules work together seamlessly,
emphasizing interoperability, data consistency, and security.

Also, testing the software under high load and in a larger system should be performed. (Scalability)
(It could be the case that those tests are not feasible, because we cannot create such a broad testing environment.)

""""""""""""""""""
Acceptance Testing
""""""""""""""""""

Acceptance testing will be conducted by the end-users with assistance from the test manager or one of the developers.
This phase will focus on validating the TrustPoint system’s usability, reliability,
and alignment with user expectations in a production-like environment.
The testing process will involve:

- Evaluating user workflows,
- trust validation,
- and secure interactions to ensure the system meets all functional requirements.

Programs will enter acceptance testing only after all critical and major defects have been resolved.

Note that we are able to test user workflows automatically at the integration test phase
but there needs to be another acceptance test phase where we actually provide manual tests.

^^^^^^^^^^
Test Tools
^^^^^^^^^^

The testing for the TrustPoint project will utilize modern testing frameworks
and tools to ensure robust and efficient validation of the application’s functionality across all levels.

""""""""""""
Unit Testing
""""""""""""

Unit testing for the core functionalities of TrustPoint will be implemented using `pytest <https://docs.pytest.org/en/stable/>`_,
a widely adopted Python testing framework.
This ensures comprehensive and automated validation of the smallest testable units.
Tests will be integrated into the defined GitHub pipelines to enable continuous integration and delivery (CI/CD).
These pipelines will ensure that any changes to the codebase are thoroughly tested before merging,
reducing the risk of regressions and enhancing development agility.

""""""""""""""""""""""""""
Integration/System Testing
""""""""""""""""""""""""""

Integration testing will leverage `Python Cucumber (behave) <https://behave.readthedocs.io/en/latest/>`_
to create behavior-driven development (BDD) test scenarios.
This approach will allow us to define tests in plain language
that are easy to understand for both technical and non-technical stakeholders.
The scenarios will focus on validating the interactions between TrustPoint components,
ensuring that they function cohesively as a system.

""""""""""""""""""
Acceptance Testing
""""""""""""""""""

The tool for acceptance testing has not been finalized at this stage.
However, efforts are underway to evaluate suitable tools that align with the requirements of end-user testing.
In the interim, manual acceptance testing will be performed in collaboration with end users
to validate the system's readiness for production.

"""""""""""""""
Data Management
"""""""""""""""

Data for testing will primarily be sourced from production-like datasets
to simulate real-world scenarios effectively.
Where necessary, synthetic data will be generated or modified using Python-based utilities to ensure test completeness.
Under no circumstances will changes be made directly to actual production data during testing activities.


-----------------------
Item Pass/Fail Criteria
-----------------------

The test process for the TrustPoint project will be considered complete once the following criteria have been met:

#. Core Functionalities Validation:
    - All critical and major defects identified during unit, integration, and system testing must be resolved.
    - The core functionalities of TrustPoint, such as certificate issuance, renewal, revocation, and domain validation, must operate reliably without workarounds.

#. Integration Testing Success:
    - The PKI components must demonstrate seamless interaction, with no critical or major integration issues.
    - Simulated high-volume certificate management scenarios should execute without performance degradation or system crashes.

#. Acceptance Testing Completion:
    - The platform must pass acceptance testing by end users, ensuring it meets their operational requirements.
    - All critical and major defects discovered during this phase must be corrected, verified, and closed.

#. Data Integrity Verification:
    - Test data generated during the system/integration and acceptance phases must validate correctly against expected outcomes, ensuring the platform’s reliability and accuracy in managing certificates.
    - Production-like scenarios must confirm data consistency across all TrustPoint modules.

#. PKI Compliance Validation:
    - TrustPoint’s processes must comply with PKI standards and security protocols.
    - Certificate data exchanges and storage must adhere to security best practices.

#. Deployment Readiness:
    - The system must pass GitHub pipeline tests, including automated unit and integration tests executed through pytest and behave, with 100% of critical tests passing.
    - The staging environment must match the production setup, with successful parallel runs simulating live scenarios for a predefined period (e.g., two weeks).

Once these criteria are satisfied, TrustPoint will be considered ready for live deployment.
Following this, any additional configurations, user onboarding,
or domain activations will occur incrementally as per readiness and validation.


-----------------------------------------------
Suspension Criteria And Resumption Requirements
-----------------------------------------------

.. csv-table:: Suspension Criteria And Resumption Requirements
   :header: "Title", "Suspension", "Resumption"
   :widths: 30, 50, 50

    "Unavailability of CA or Domain Validation Services", "Testing will be paused if the certificate authority (CA) or domain validation services are unavailable, as these are critical for validating PKI-related functionalities.", "Testing will resume once the CA or validation services are operational, and any interrupted test cases will be re-executed to ensure completeness."
    "Critical Defect Identified in Core Functionality", "If a critical defect in core features (e.g., certificate issuance, revocation, or renewal) is identified during testing, further testing will be suspended until the issue is resolved.", "Testing will resume once the defect is fixed and verified in the development environment."
    "Test Environment Instability", "Testing will pause if the staging or testing environment becomes unstable or misconfigured, as this could lead to unreliable results.", "Testing will resume after the environment is restored to a stable and functional state, and necessary validations have been performed."
    "Unavailability of Required Test Data", "If critical test data (e.g., domain configurations, certificate requests) is unavailable or incomplete, testing will be suspended for the affected areas.", "Testing will resume once sufficient test data has been prepared and verified."
    "Staffing or Resource Constraints", "If key personnel (e.g., test managers or developers) or resources (e.g., access to tools or infrastructure) are unavailable, testing may be delayed for impacted areas.", "Testing will resume once adequate staffing and resources are available to continue the process effectively."


-----------------
Test Deliverables
-----------------

The following consolidated deliverable will be provided at the conclusion of the TrustPoint testing process:

*Comprehensive Test Report:*

This single document will include the following components:

#. Unit Test Results:
    - Summary of pytest executions, including test case descriptions, pass/fail status, and defect details.
    - Logs and outputs from automated tests executed through GitHub pipelines.

#. Integration Test Results:
    - Results from behavior-driven integration tests using the Python Cucumber framework (behave).
    - Detailed logs of test scenarios, their outcomes, and any identified issues.

#. Defect and Incident Reports:
    - A summary of defects encountered during testing phases, their resolution status, and associated incident logs.

#. Acceptance Testing Summary:
    - Results of acceptance tests, including user feedback and final approval status.
    - Any open issues and their planned resolutions (if applicable).

#. Coverage Metrics:
    - Test coverage statistics to demonstrate the completeness of testing efforts.


--------------------
Remaining Test Tasks
--------------------

.. csv-table:: Remaining Test Tasks
   :header: "Task", "Assigned To", "Status"
   :widths: 60, 20, 15

   "Collect and finalize testing requirements (e.g., PKI workflows, certificate lifecycle scenarios).", "TM, PM, Client", "In Progress"
   "Define and finalize acceptance criteria for TrustPoint’s features.", "TM, PM, Client", "Pending"
   "Configure and validate the test environments (development and staging).", "TM, Dev", "In Progress"
   "Develop unit tests using pytest for core functionalities (e.g., certificate issuance, renewal, and revocation).", "Dev", "In Progress"
   "Develop integration tests using behave (Python Cucumber framework) for end-to-end workflows.", "TM, Dev", "Pending"
   "Execute system/integration tests in the staging environment.", "TM, Dev", "Not Started"
   "Document results from unit, integration, and acceptance tests for inclusion in the comprehensive test report.", "TM", "Not Started"
   "Conduct acceptance testing with end users (e.g., system administrators, security teams).", "TM, Client", "Not Started"
   "Resolve defects identified during testing and retest as needed.", "Dev", "Ongoing"
   "Finalize and deliver the comprehensive test report (including test results and coverage).", "TM", "Not Started"


-------------------
Environmental Needs
-------------------

The following elements are required to support the testing effort at all levels within the TrustPoint project:

#. Access to Development and Staging Environments:
    - A dedicated development environment for initial testing, debugging, and iterative fixes.
    - A staging environment that mirrors the production setup for system, integration, and acceptance testing.

#. Certificate Authority (CA) Setup:
    - Access to a functional CA system to validate PKI-related features such as certificate issuance, renewal, and revocation.

#. GitHub CI/CD Pipeline Configuration:
    - An operational GitHub pipeline to automate testing and deployment workflows. This pipeline will execute unit and integration tests using pytest and behave frameworks.

#. Database Access:
    - Availability of a testing database populated with production-like data to simulate realistic scenarios.
    - A clear separation between testing and production data to ensure no overlap or accidental data modification.

#. Secure Networking Configuration:
    - A secure network environment for testing interactions between TrustPoint components, including domain validation and security protocol testing.

#. Access to Backup/Recovery Processes:
    - Access to nightly backup and recovery tools for safeguarding test environment data.

#. Testing Tools:
    - Functional installations of pytest and behave for automated testing.
    - Additional tools may be added as acceptance testing needs evolve.

This streamlined setup ensures an effective and efficient testing process while minimizing redundancy and complexity.


---------------------------
Staffing And Training Needs
---------------------------

#. Staffing Requirements
    - At least one dedicated tester should be assigned for the integration and acceptance testing phases to ensure thorough and independent validation.
    - In the absence of a dedicated tester, the test manager will assume this role with support from the development team.
    - Developers will assist in test case creation and debugging during the unit testing and integration testing phases.

#. Training Needs
    - Developers and Testers:
        - Familiarity with TrustPoint’s core functionality, including certificate issuance, renewal, revocation, and domain validation workflows.
        - Training on pytest for unit testing and behave for integration testing, including understanding the GitHub pipeline integration.

    - End Users:
        - Training on navigating TrustPoint’s user interfaces, configuring domains, and interpreting system-generated reports.


----------------
Responsibilities
----------------

.. csv-table:: Responsibilities
   :header: "Responsibility", "TM", "PM", "Dev", "Test Team", "Client"
   :widths: 40, 10, 10, 10, 15, 10

   "Acceptance Test Documentation & Execution", "X", "X", "", "X", "X"
   "System/Integration Test Documentation & Execution", "X", "X", "X", "X", ""
   "Unit Test Documentation & Execution", "X", "", "X", "", ""
   "System Design Reviews", "X", "X", "X", "X", "X"
   "Detailed Design Reviews", "X", "X", "X", "X", ""
   "Test Procedures and Rules", "X", "X", "X", "X", ""
   "Change Control and Regression Testing", "X", "X", "X", "X", ""
   "Certificate Lifecycle Scenarios Review", "X", "X", "X", "", "X"


--------
Schedule
--------

The following schedule outlines the remaining testing activities.
These activities are aligned with the project's current progress and emphasize completing testing efficiently and effectively.
Specific dates and durations should be detailed in the project timeline managed by the project manager
in collaboration with development and test leads.

.. csv-table:: Testing Schedule Table
   :header: "Activity", "Responsibility", "Duration/Timeline", "Details"
   :widths: 30, 30, 20, 60

   "Review Requirements Document", "Test Team, Dev, PM", "1 Week", "Review requirements to ensure complete understanding and alignment of test objectives."
   "Finalize and Review Requirements", "TM, PM, Test Team", "1 Week", "Develop and review the requirements needed for writing the acceptance tests."
   "Review System Design Document", "Test Team, Dev", "3 Days", "Enhance understanding of the system structure and refine test objectives."
   "Conduct Unit Tests", "Dev", "Ongoing until code completion", "Verify individual methods/functions as they are completed; results reviewed by the development lead."
   "System/Integration Testing", "Test Team, Dev", "2 Weeks", "Validate module interactions, data flow, and PKI processes in a staging environment."
   "Acceptance Testing", "Test Team, End Users, PM", "2 Weeks", "Perform final user-driven testing to ensure TrustPoint meets functional and usability expectations."


--------------------------------
Planning Risks And Contingencies
--------------------------------

.. csv-table:: Planning Risks And Contingencies
   :header: "Risk", "Description", "Contingency Plan"
   :widths: 30, 50, 50

   "Limited Staff Availability for Testing", "Key stakeholders or end users may have limited availability during acceptance testing.", "Schedule testing in advance; assign a test team representative if stakeholders are unavailable."
   "Incomplete or Changing Requirements", "Requirements may evolve or be incomplete, leading to rework or missed test cases.", "Conduct iterative reviews; adopt agile testing practices to adapt dynamically to changes."
   "Test Environment Instability", "The staging or test environment may become misconfigured or unavailable, causing delays.", "Maintain backup environments; use configuration checklists to ensure reliable setups."
   "Delays in Defect Resolution", "Defects may take longer to resolve, impacting subsequent testing phases.", "Prioritize critical defects; allocate additional resources for prompt resolution."
   "Dependence on External Systems", "External PKI components (e.g., Certificate Authorities) may be unavailable during testing.", "Use mock services or simulators; coordinate with service providers to ensure availability."
   "Inadequate Test Data", "Insufficient or unrealistic test data may result in incomplete testing or missed edge cases.", "Generate synthetic data using Python utilities; use anonymized production-like datasets for validation."


---------
Approvals
---------

----------
Test Cases
----------

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

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../trustpoint/features/R_001.feature
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

.. literalinclude:: ../../trustpoint/features/R_002.feature
   :language: gherkin

^^^^^
R_003
^^^^^

This testcase is related to requirement `R_003`_.

"""""""""
Test Idea
"""""""""

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../trustpoint/features/R_003.feature
   :language: gherkin

^^^^^
R_004
^^^^^

This testcase is related to requirement `R_004`_.

"""""""""
Test Idea
"""""""""

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../trustpoint/features/R_004.feature
   :language: gherkin

^^^^^
R_005
^^^^^

This testcase is related to requirement `R_005`_.

"""""""""
Test Idea
"""""""""

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../trustpoint/features/R_005.feature
   :language: gherkin

--------
Glossary
--------

.. csv-table:: Glossary
   :header: "Abbreviation", "Definition"
   :widths: 50, 50

    "TM", "Test Manager"
    "PM", "Project Manager"
    "Dev", "Development Team"
    "Client", "Stakeholders or End Users"
