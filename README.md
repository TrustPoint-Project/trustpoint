<p align="center">
  <img alt="Trustpoint" src="/.github-assets/trustpoint_banner.png"><br/>
  <strong>The open source trust anchor software for machines and factories to manage digital identities.</strong><br/><br/>
  <a href="https://trustpoint.campus-schwarzwald.de/en/"><img src="https://img.shields.io/badge/Landing_Page-014BAD?style=flat"></a>
  <a href="https://github.com/orgs/TrustPoint-Project/discussions"><img src="https://img.shields.io/badge/GitHub-Discussions-014BAD?style=flat"></a>
  <a href="https://trustpoint.readthedocs.io"><img src="https://img.shields.io/readthedocs/trustpoint"></a>
  <a href="https://hub.docker.com/r/trustpoint2023/trustpoint"><img src="https://img.shields.io/docker/automated/trustpoint2023/trustpoint"></a> 
  <img src="https://img.shields.io/badge/License-MIT-014BAD?style=flat">
  <img src="https://img.shields.io/badge/Status-Beta-red?style=flat">
</p>

![Pytest Status](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg)
![Coverage](https://codecov.io/gh/TrustPoint-Project/trustpoint/branch/main/graph/badge.svg)
![MyPy Status](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg)
![Ruff Status](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg)

> [!CAUTION]
> Trustpoint is currently in a **technology preview** (beta) state. Do not use it in production.

## Why Trustpoint?

The secure integration of components and applications into a domain is a major challenge. Many processes established in
IT cannot be mapped 1:1 at factory level. The reasons for this range from highly segmented networks and devices with
limited resources (constrained devices) to components with a service life that can sometimes be 20 years or more.

Users are therefore faced with various challenges, which in practice often lead to digital identities not being
implemented at all or inadequately.

Trustpoint makes it possible to abstract the complexity in industrial environments and offer users simple workflows for
managing their components and the associated digital identities.

Existing solutions often do not meet the needs of users, as they only offer an isolated view for individual applications
or attempt to transfer common IT mechanisms to factory environments, which are not applicable in this way.

As a result, Trustpoint aims to offer a solution tailored to the domain of machine builders and machine operators

- that offers workflows for managing digital identities

- that does not require users to have any prior knowledge of cryptographic mechanisms

- supports concepts for zero-touch onboarding as well as user-driven onboarding

## What are the features of this early technology preview?

### 1. Device Onboarding

- **[Trustpoint Client](https://github.com/TrustPoint-Project/trustpoint-client)**: Simple onboarding through a client
  interface.
- **Command-Line Interface (CLI)**: Onboard devices manually via Linux commands.
- **Browser-Based Onboarding**: Use a web interface for easy onboarding.
- **PKCS#12 File**: Download certificate files for manual installation.

### 2. Application Certificate Management

- **Certificate Requests**: Issue certificates for apps or systems.

### 3. Certificate Authority (CA) Modes

- **Import Issuing CA**: Integrate with an existing PKI by importing external CAs.
- **Self-Generated CA**: Create a root and issuing CA for testing purposes.

### 4. Miscellaneous

- **User Interface**: Manage certificates and devices through an intuitive web-based UI.
- **Dashboard**: View device and certificate statuses.
- **Deployment**: Easily deploy TrustPoint using Docker for simplified installation and scaling.
- **Certificate Management Protocol (CMP)**: Supports CMP for automated certificate management, allowing easy
  integration with other CMP-compliant systems.

## Who is developing Trustpoint?

Trustpoint is currently being developed by a consortium of five organizations: Campus Schwarzwald, Keyfactor, achelos
GmbH, Hamm-Lippstadt University of Applied Sciences and asvin GmbH. Several industrial companies are also part of the
project as associated partners. These include ARBURG GmbH + Co KG, Belden Inc., Diebold Nixdorf, Homag GmbH, J. Schmalz
GmbH, PHOENIX CONTACT GmbH & Co. KG and Siemens AG.

Trustpoint is funded as part of a project sponsored by the German Federal Ministry of Education and Research. Questions
can be asked in [Discussions](https://github.com/orgs/TrustPoint-Project/discussions) and will be answered by us. We
look forward to hearing about your experiences with Trustpoint. You can send suggestions to
trustpoint@campus-schwarzwald.de.

## Documentation and Installation Instructions

For more details see the full [Trustpoint Documentation](https://trustpoint.readthedocs.io/en/latest/) as well as
the full [Trustpoint-Client Documentation](https://trustpoint-client.readthedocs.io/en/latest/).

For a quick setup and first impression use
our [Quickstart Setup Guide](https://trustpoint.readthedocs.io/en/latest/quickstart_setup.html#)

### Dockerhub

We are also providing the Trustpoint as a docker-container. Please see [Trustpoint on Dockerhub] or follow the
instructions in our [Trustpoint Documentation](https://trustpoint.readthedocs.io/en/latest/) to build the
container yourself.

## What features/requirements are finished and which are still w.i.p.?

There are some requirements defined inside
the [Test Plan](https://trustpoint.readthedocs.io/en/test_plan/test_plan.html)
which are listed in
the [chapter Requirements](https://trustpoint.readthedocs.io/en/test_plan/test_plan.html#requirements).
To keep this README as short as possible but still as informative as possible,
we will state the requirements defined in
the [Test Plan](https://trustpoint.readthedocs.io/en/test_plan/test_plan.html),
state the header and if the [pyhon behave](https://behave.readthedocs.io/en/latest/) tests are passing or failing.

| Requirement | Title                                                           | Status of the behave test                                                                                    |
|-------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| R_001       | Create, view, edit and delete an identity                       | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_001_feature_test.yml/badge.svg) |
| R_002       | Usage of any zero touch onboarding protocol                     | No test present.                                                                                             |
| R_003       | Certificate Lifecycle Management                                | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_003_feature_test.yml/badge.svg) |
| R_004       | REST API                                                        | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_004_feature_test.yml/badge.svg) |
| R_005       | Docker Container Support                                        | No test present.                                                                                             |
| R_006       | Backup, Restore, and Update Mechanisms                          | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_006_feature_test.yml/badge.svg) |
| R_007       | Logging Capabilities                                            | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_007_feature_test.yml/badge.svg) |
| R_008       | Auto-Generated Issuing CAs                                      | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_008_feature_test.yml/badge.svg) |
| R_009       | High Availability                                               | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_009_feature_test.yml/badge.svg) |
| R_010       | CMP Endpoint for Onboarded Devices                              | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_010_feature_test.yml/badge.svg) |
| R_011       | EST Endpoint for Onboarded Devices                              | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_011_feature_test.yml/badge.svg) |
| R_012       | Language Selection and Translation                              | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_012_feature_test.yml/badge.svg) |
| R_013       | Remote Credential Download                                      | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_013_feature_test.yml/badge.svg) |
| R_101       | Devices are only allowed to communicate with valid certificates | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_101_feature_test.yml/badge.svg) |
| R_102       | Encrypted Communication                                         | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_102_feature_test.yml/badge.svg) |
| R_103       | Security Level Configuration                                    | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_103_feature_test.yml/badge.svg) |
| R_104       | Certificate Template Security                                   | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/r_104_feature_test.yml/badge.svg) |
| F_001       | NTEU must be able to execute R_001 and R_002.                   | ![Test](https://github.com/TrustPoint-Project/trustpoint/actions/workflows/f_001_feature_test.yml/badge.svg) |
