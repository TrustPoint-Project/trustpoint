.. _quickstart_setup_link:

Quickstart Setup Guide
===========================

This guide provides an introduction to Trustpoint and instructions for setting up the Trustpoint using Docker.

Introduction 🌐
---------------
**Trustpoint** is a collaborative project dedicated to securing industrial environments through digital identities for machines and components. It addresses cybersecurity challenges in increasingly interconnected industrial settings by managing machine identities3. Trustpoint offers an open-source solution for secure, scalable management of digital identities, leveraging methods such as Zero-Touch Onboarding (based on standards like BRSKI) and user-driven onboarding for legacy or specialized systems.

**Project Team**

The Trustpoint development team consists of medium-sized companies (achelos, asvin, Keyfactor) with expertise in the field of security as well as research institutions and universities (Schwarzwald Campus, Hamm-Lippstadt University of Applied Sciences).
The practical relevance to the user is guaranteed by the close dialogue with our associated partners ARBURG, Belden Inc, HOMAG, Phoenix Contact, Schmalz, Siemens and Diebold Nixdorf.

**Funding**

The project has been funded by the German Federal Ministry of Education and Research since September 2023.

--------------------------------------

Getting Started with Docker 🐳
------------------------------

Prerequisites ✅
^^^^^^^^^^^^^^^^
Make sure you have the following installed:

1. **Docker**: Version 20.10 or higher.
2. **Git**: To clone the Trustpoint repository.

Step-by-Step Setup 🔧
^^^^^^^^^^^^^^^^^^^^^

1. **Clone the Trustpoint Repository**

   First, clone the Trustpoint source code from the official repository:

   .. code-block:: bash

       git clone https://github.com/TrustPoint-Project/trustpoint.git
       cd trustpoint

   This command downloads the Trustpoint source code to your local machine and navigates into the project directory.

2. **Build the Trustpoint Docker Image**

   Use Docker to build the Trustpoint image from the source:

   .. code-block:: bash

       docker build -t trustpoint .

   - **-t trustpoint**: Tags the image with the name `trustpoint`.
   - **.**: Specifies the current directory as the build context.

3. **Run the Trustpoint Container with a Custom Name and Port Mappings** 🚀

   Start the Trustpoint container using the image you just built, with a custom name and both port mappings:

   .. code-block:: bash

       docker run -d --name trustpoint-container -p 80:80 -p 443:443 trustpoint

   - **-d**: Runs the container in detached mode.
   - **--name trustpoint-container**: Names the container `trustpoint-container`.
   - **-p 80:80**: Maps the container's HTTP port to your local machine's port 80.
   - **-p 443:443**: Maps the container's HTTPS port to your local machine's port 443.

4. **Verify the Setup** 🔍

   Once the container is running, you can verify the setup:

   - **Web Interface**: Open `https://localhost` in your browser to access the Trustpoint interface.
   - **Default Credentials**: Use the following login information to access the Trustpoint interface:

     - **Username**: `admin`
     - **Password**: `testing321`

   .. note::

      You may need to accept a self-signed certificate in your browser to proceed.


.. admonition:: 🥳 CONGRATULATIONS!
   :class: tip

   You’ve successfully set up Trustpoint! Your environment is now ready to securely manage digital identities for your industrial devices. You can start registering devices, issuing certificates, and building a trusted network.

5. **Change the Current Admin User Password** 🔑

   To secure your Trustpoint setup, it's important to change the default admin user password:

   - Click on the **Users** section in the Django admin dashboard.
   - Select the **admin** user from the list.
   - Scroll down to the **password field** and click the "change password" link.
   - Enter and confirm the new password.
   - Click **Save** to update the password.

Tips and Troubleshooting 🧰
---------------------------

- **View Logs**: For troubleshooting, view logs with:

  .. code-block:: bash

      docker logs -f trustpoint-container

- **Stop and Remove the Container**: Stop and remove the container with:

  .. code-block:: bash

      docker stop trustpoint-container && docker rm trustpoint-container


What to Do Next ➡️
------------------

After setting up and Trustpoint, here are some recommended next steps to explore the full capabilities of the platform:

1. **Explore Trustpoint with test data** 🧪:
   Familiarize yourself with Trustpoint’s functionalities by running it with sample test data. To populate test data, navigate to **Home > Notifications > Populate Test Data** in the Trustpoint interface.

2. **Use the Trustpoint in conjunction with the Trustpoint Client** 💻:
   The easiest way to fully utilize Trustpoint is by pairing it with the associated Trustpoint Client, which is installed on end devices. The client enables streamlined identity management and certificate issuance. For more details, visit the [Trustpoint Client GitHub repository](https://github.com/TrustPoint-Project/trustpoint-client).

3. **Issue your first certificate for an end device** 🛡️:
   To do this, you need an Issuing CA certificate, a domain and a device that you must define in Trustpoint. Therefore follow the steps described in :ref:`quickstart_operate_link`


