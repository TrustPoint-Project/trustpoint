Frequently Asked Questions (FAQ)
================================

What is TrustPoint?
----------------------
TrustPoint is an open-source solution designed to manage digital certificates in industrial networks securely. It assists companies in verifying trust chains, thereby enhancing the security of machines and their components within factories.

Who can benefit from TrustPoint?
-----------------------------------
TrustPoint is tailored for industrial users, particularly in mechanical engineering and manufacturing industries, who require efficient management of digital identities and certificates.


Who is (mainly) developing TrustPoint?
--------------------------------
The development team comprises:

- **Companies:**
  - achelos
  - asvin
  - Keyfactor

- **Research Institutions and Universities:**
  - Campus Schwarzwald
  - Hochschule Hamm-Lippstadt

Who are the associated partners of TrustPoint?
-------------------------------------------------
Associated partners include:

- ARBURG GmbH + Co KG
- Belden Inc.
- HOMAG GmbH
- Phoenix Contact
- J. Schmalz GmbH
- Siemens AG
- Diebold Nixdorf


How is TrustPoint funded?
----------------------------
TrustPoint is funded by the German Federal Ministry of Education and Research since September 2023.

How can I ask questions or provide feedback about TrustPoint?
----------------------------------------------------------------
You can ask questions in the Discussions section of the GitHub repository, and the team will respond. Additionally, suggestions can be sent to `trustpoint@campus-schwarzwald.de`.

What technologies does TrustPoint use?
-----------------------------------------
The current version of TrustPoint uses a Python Django framework.

How can I set up the development environment for TrustPoint?
---------------------------------------------------------------
To set up the development environment, follow these steps:

- **Install Python**: Ensure Python 3.12.2 is installed. Using `pyenv` is recommended for managing different Python versions.
- **Install Poetry**: Use Poetry to create a virtual environment and manage dependencies.
- **Install Dependencies**: Navigate to the project root and run `poetry install`.
- **Activate the Environment**: Run `poetry shell` to activate the virtual environment.
- **Set Up the Database**: Navigate to the `trustpoint` directory and run the following commands:

  .. code-block:: bash

     python manage.py makemigrations
     python manage.py migrate
     python manage.py createsuperuser

- **Run the Development Server**: Start the server with `python manage.py runserver`.

How can I build and run TrustPoint using Docker?
---------------------------------------------------
To build and run TrustPoint as a Docker image:

- **Build the Docker Image**: Navigate to the project's root directory and run:

  .. code-block:: bash

     docker build -t trustpoint .

- **Run the Docker Container**: Once the image is built, run:

  .. code-block:: bash

     docker run -d --name trustpoint-container -p 80:80 -p 443:443 trustpoint

How can I contribute to the TrustPoint project?
--------------------------------------------------
Contributions are welcome. You can fork the repository, make your changes, and submit a pull request. Ensure that your contributions align with the `project's guidelines and standards <https://github.com/TrustPoint-Project/trustpoint/blob/main/AUTHORS.md>`_.

8. What license does TrustPoint use?
------------------------------------
TrustPoint is released under the MIT license. This allows for broad usage, modification, and distribution of the software, promoting open collaboration and development. You can find the license `here <https://github.com/TrustPoint-Project/trustpoint/blob/main/LICENSE>`_
