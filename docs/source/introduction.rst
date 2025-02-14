Introduction
============

Welcome to the Trustpoint Documentation. This guide provides comprehensive information to help you understand, use, and contribute to the Trustpoint project.

What is Trustpoint?
-------------------

Trustpoint is an open-source platform designed to simplify and enhance public key infrastructure (PKI) management. It aims to deliver secure, efficient, and scalable solutions for managing digital certificates, domains, and security protocols for industrial environments.

Key Features of Trustpoint
--------------------------

- Comprehensive Certificate Lifecycle Management (CLM)
- Support for short-lived certificates
- Standardized interfaces (CMP, EST, REST)
- User-friendly web-based application
- Low hardware requirements
- Availability as a Docker container
- Built on Python Django framework

How to Navigate the Documentation
---------------------------------

The documentation is organized into the following main sections:

- **Getting started**: An overview of Trustpoint’s structure and how its components interact.
- **Architecture**: An overview of Trustpoint’s structure and how its components interact.
- **User Interface Guides**: Instructions on using the GUI for managing issuing CAs, domains, and other key functions.
- **PKI**: In-depth information on public key infrastructure concepts and implementations within Trustpoint.
- **API Reference**: A comprehensive guide to the Trustpoint API for developers.

Getting Started
---------------

To begin using Trustpoint, we recommend exploring the :ref:`Quickstart Setup Guide` section to familiarize yourself with the core features and setup. For detailed information on PKI concepts and best practices, refer to the "PKI" section.

Users and Scenarios
-------------------

Trustpoint is designed to cater to a wide range of users and scenarios, making it an ideal solution for organizations and projects with varying certificate management needs. Here’s an overview of who would benefit most from using Trustpoint and the scenarios where it excels:

1. **Target Users:**

   - **Small to Medium Enterprises (SMEs)**: Organizations that need a straightforward, cost-effective way to manage digital certificates without a complex PKI infrastructure.
   - **Development Teams**: Teams working on software or applications in machinery that require secure communication and need a testing environment for certificates.
   - **IT Administrators**: Professionals responsible for managing and securing network infrastructure.

2. **Ideal Scenarios for Using Trustpoint:**

   - **Development and Testing Environments**: Trustpoint's ability to generate self-signed Root and Issuing CAs makes it a perfect tool for testing certificate workflows in non-production environments.
   - **Air-Gapped Environments**: Trustpoint can operate using an imported Issuing CA, making it suitable for environments that are not connected to external networks and require tight security controls.
   - **Device Onboarding for IIoT and Network Devices**: Trustpoint simplifies the process of onboarding devices securely, making it well-suited for IoT deployments and network infrastructure that rely on certificate-based authentication.
   - **Certificate Management for on prem**: For organizations needing to manage certificates for internal services and applications, Trustpoint provides an efficient and user-friendly solution.
   - **Organizations without a Dedicated PKI**: Trustpoint is suitable for teams or companies that lack a dedicated PKI but need reliable certificate management features to secure their operations.



