.. _onboarding_link:

Onboarding Mechanisms
===================================

This document outlines the different mechanisms available to onboard devices to Trustpoint, including user-driven and automated methods. These methods aim to streamline the process of issuing initial certificates that are used for secure device authentication with Trustpoint.

Overview
--------
Trustpoint provides multiple ways to onboard a device. Currently, the primary onboarding mechanism is user-driven, with zero-touch onboarding being a future enhancement. The following sections provide detailed information on each of these methods.

Onboarding a device to Trustpoint involves issuing an initial certificate, which allows the device to securely authenticate with Trustpoint. There are two categories of onboarding available: user-driven onboarding and zero-touch onboarding.

User-Driven Onboarding
----------------------
User-driven onboarding is the primary method available for onboarding devices to Trustpoint. This method offers several options, depending on the user's preferences and available resources.

Using the Trustpoint Client
^^^^^^^^^^^^^^^^^^^^^^^^^^^
Trustpoint provides a user-friendly client application that simplifies the onboarding process. The Trustpoint client is available at `Trustpoint Client GitHub <https://github.com/TrustPoint-Project/trustpoint-client>`_. This method is recommended for users who prefer a guided approach to onboarding.

How It Works:

- A new device with the Onboarded protocol **Trustpoint client** is added to Trustpoint
- In **Devices** click **Start Onboarding** on the new device
- Copy the provided command to your clipboard and execute it on the device
- The device is onboarded
- During the process, an initial certificate is issued, enabling secure device authentication with Trustpoint.

Requirements:

- Access to the Device.
- Python 3.10 or greater on device.
- Trsutpoint client installed on the device (via `pip install trustpoint-client`).
- An connection to communicate with Trustpoint services.

Using the CLI of a Linux Machine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Users can also onboard their device manually by executing commands on a Linux machine. This option is suitable for advanced users comfortable with the command line interface (CLI).

How It Works:

- A new device with the Onboarded protocol **Device CLI** is added to Trustpoint
- In **Devices** click **Start Onboarding** on the new device
- Copy the provided commands to your clipboard and execute it on the device
- Upon successful submission, the device is issued an initial certificate for authentication.

Requirements:

- A Linux machine with access to the command line.
- Necessary permissions.
- An connection to communicate with Trustpoint services.

Browser-Based Onboarding
^^^^^^^^^^^^^^^^^^^^^^^^
Trustpoint also offers browser-based onboarding, allowing users to onboard their devices conveniently through a web interface. This method is ideal for users who prefer a straightforward, intuitive onboarding experience without needing to install additional software.

How It Works:

- A new device with the Onboarded protocol **Browser download** is added to Trustpoint
- In **Devices** click **Start Onboarding** on the new device
- Open a browser on your device
- Visit the provided Download URL
- Copy / Paste the Device ID and the provided OTP in the form
- Click **Download credentials**
- Click **Download PKCS12**

Requirements:

- A web browser.
- An connection to access the onboarding web page.

Manual Download of a P12 File
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In cases where the is no direct connection to Trustpoint, they can download a PKCS#12 (.p12) format file containing the device certificate or a separate key and certificate in PEM  and distribute it manually to the target machine. This approach can be useful for integrating with legacy systems or for offline onboarding scenarios.

How It Works:

- A new device with the Onboarded protocol **Manual download** is added to Trustpoint
- In **Devices** click **Start Onboarding** on the new device
- Click **Download PKCS12** or **Download PEM**
- The user manually transfers the .p12 or .pem file to the target device and imports it.

Requirements:

- Ability to download and securely transfer the .p12 file.

Zero-Touch Onboarding (Work in Progress)
----------------------------------------
Trustpoint is actively developing a zero-touch onboarding feature. This mechanism will allow fully automated onboarding without any user intervention, simplifying the process even further. Zero-touch onboarding is designed for use in environments where many devices need to be onboarded without manual effort, providing a scalable solution for large deployments.

How It Works:

- Devices are pre-configured with Trustpoint information before deployment.
- Upon connecting to the network, the device automatically requests and receives an initial certificate, completing the onboarding process without user interaction.

Requirements:

- Network infrastructure to support automated onboarding.

Summary
-------
Trustpoint offers a variety of mechanisms for device onboarding, ranging from user-driven methods with flexible options to future plans for automated zero-touch onboarding. Users can choose the method that best fits their needs, whether it's through the Trustpoint client, a web interface, or manual distribution.
