<p align="center">
  <img alt="Trustpoint" src="/.github-assets/trustpoint_banner.png"><br/>
  <strong>The open source trust anchor software for machines and factories to manage digital identities.</strong><br/><br/>
  <a href="https://trustpoint.campus-schwarzwald.de/"><img src="https://img.shields.io/badge/Landing_Page_(german)-014BAD?style=flat"></a>
  <a href="https://github.com/orgs/TrustPoint-Project/discussions"><img src="https://img.shields.io/badge/GitHub-Discussions-014BAD?style=flat"></a>
  <img src="https://img.shields.io/badge/License-MIT-014BAD?style=flat">
  <img src="https://img.shields.io/badge/Status-Early_technology_preview-red?style=flat">
</p>

> [!CAUTION]
> Trustpoint is currently in an **early technology preview** (alpha) state. Do not use it in production.

## Why Trustpoint?

The secure integration of components and applications into a domain is a major challenge. Many processes established in IT cannot be mapped 1:1 at factory level. The reasons for this range from highly segmented networks and devices with limited resources (constrained devices) to components with a service life that can sometimes be 20 years or more.

Users are therefore faced with various challenges, which in practice often lead to digital identities not being implemented at all or inadequately.

Trustpoint makes it possible to abstract the complexity in industrial environments and offer users simple workflows for managing their components and the associated digital identities.

Existing solutions often do not meet the needs of users, as they only offer an isolated view for individual applications or attempt to transfer common IT mechanisms to factory environments, which are not applicable in this way.

As a result, Trustpoint aims to offer a solution tailored to the domain of machine builders and machine operators

- that offers workflows for managing digital identities

- that does not require users to have any prior knowledge of cryptographic mechanisms

- supports concepts for zero-touch onboarding as well as user-driven onboarding


## What are the features of this early technology preview?

- Django-based responsive GUI
- Manage Issuing CAs via PKCS12, PEM, or request from external PKI via EST
- Lightweight PKI (local root CA) for testing and evaluation purposes
- Demo of user-driven onboarding with [Trustpoint Client](https://github.com/TrustPoint-Project/trustpoint-client)
- Manual device onboarding via CLI and PKCS12 export
- Device management table
- Demo home visualization update
- Sample configuration views

## Who is developing Trustpoint?

Trustpoint is currently being developed by a consortium of five organizations: Campus Schwarzwald, Keyfactor, achelos GmbH, Hamm-Lippstadt University of Applied Sciences and asvin GmbH. Several industrial companies are also part of the project as associated partners. These include ARBURG GmbH + Co KG, Homag GmbH, J. Schmalz GmbH, PHOENIX CONTACT GmbH & Co. KG, FANUC Deutschland GmbH and Siemens AG.

Trustpoint is funded as part of a project sponsored by the German Federal Ministry of Education and Research. Questions can be asked in [Discussions](https://github.com/orgs/TrustPoint-Project/discussions) and will be answered by us. We look forward to hearing about your experiences with Trustpoint. You can send suggestions to trustpoint@campus-schwarzwald.de.

## Installation

The current version uses a Python Django framework.  
We are using pyenv and poetry to manage different python versions and dependencies.

Please note that the current version is in **early development status** and still subject to **major changes**. Our aim is to make an operational version of the software available quickly in order to receive as much feedback as possible from users.

### Pyenv

[OPTIONAL]
You can use pyenv to install and manage different Python versions in parallel.  
To install it, install all [required build dependencies](https://github.com/pyenv/pyenv/wiki#suggested-build-environment).

Then follow the [installation manual](https://github.com/pyenv/pyenv?tab=readme-ov-file#installation).

You can add the following to your .bashrc:

```shell
export PATH="$PATH:/home/<your-user-name>/.pyenv/bin/"

export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

Restart your shell

```shell
exec "$SHELL"
```

You can install the desired python version as follows

```shell
pyenv install 3.12.2
pyenv global 3.12.2
```

### Poetry

You should use poetry to create a virtual environment and to manage the dependencies (instead of pip directly).  
The easiest way to install poetry is their offered [installer](https://python-poetry.org/docs/#installing-with-the-official-installer)

You can also follow the manual steps, without just executing a downloaded script (security wise, the better decision).

You can add the following to your .bashrc

```shell
export PATH="$PATH:/home/<your-user-name>/.local/bin/"
```

To configure the python environment, see [the Poetry documentation on managing environments](https://python-poetry.org/docs/managing-environments/)

If you are using pyenv, make sure to add the following configuration:

```shell
poetry config virtualenvs.prefer-active-python true
```

### Install dependencies with poetry.

If you have an existing virtual environment, e.g. through using python3 -m venv,
exit the virtual environment (that is make sure you are not in the environment).
You can usually exit it with:

```shell
deactivate
```

Then, remove any virtual environment you may have set up, e.g. .venv/ directory.

Finally, install everything through poetry:

```shell
cd /path/to/trustpoint/
poetry install
```

### Activating the environment

```shell
poetry shell
```

You can now use the manage.py file as usual.

#### Setting up the DB and SuperUser

Firstly, we need to create a sqlite database for development, migrate / create the required tables and create
a superuser. The superuser credentials can later be used to access the admin page: localhost:8000/admin/.

```bash
cd trustpoint
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

Use any database client to connect to the database. you need to configure two settings
- database type : SQLite
- database file path: path to `db.sqlite3` file in trustpoint folder

#### Running the development server

```bash
python manage.py runserver
```

You can then access the GUI through localhost:8000.

Alternatively, use the following command to run a development HTTPS server (self-signed certificate).

```bash
python manage.py runserver_plus 8000 --cert-file ../tests/data/x509/https_server.crt --key-file ../tests/data/x509/https_server.pem
```

#### Logging in

Browsing to any page should redirect you to the login page.
The login page can be accessed directly via /users/login/.

Use the username and password which you previously provided through the **createsuperuser** command.

#### Management commands for testing and development purposes

```bash
python manage.py clear_db
```

Clears all IssuingCA, EndpointProfile, and Device instances from the database.

```bash
python manage.py init_demo
```

Populates the database with some example CA and device instances.

```bash
python manage.py makemsg -l de
python manage.py makemsg -l de -d djangojs
```

Makes the translation (.po) files from translatable strings. gettext must be installed on your system.

```bash
python manage.py compilemsg
```

Compiles the translation files (.po) to binary (.mo) files actually used by Django.

#### Building auto documentation

```bash
cd ../docs
sphinx-apidoc -f -e -o ./source ../trustpoint /*/migrations/*
make html
```

#### Adding dependencies to the project

Dependencies generally required for the project can be added using the following:

```shell
poetry add <name-of-package>
```

Dependencies that are only required in development, use the following to add in within the dev section:

```shell
poetry add --group=dev <name-of-package>
```

#### Using the ruff linter and formatter

For linting everything in the current directory use:

```shell
ruff check .
```

For active formatting everything in the current directory use:

```shell
ruff format .
```

### Docker

You can also build and run Trustpoint as a Docker image.

1. Build the Docker image:

   - Open a terminal and navigate to your project's root directory.
   - Run the following command to build the Docker image:

   ```
   docker build -t trustpoint .
   ```

2. Run the Docker container:
   - Once the image is built, you can run a container based on that image:
   ```
   docker run -p 8000:8000 trustpoint
   ```

## Usage

### Demo Onboarding using Trustpoint Client on localhost

- make sure your database schema is up to date

```
python manage.py makemigrations
python manage.py migrate
```

- Start Trustpoint developer server with HTTPS (runserver_plus)
- Add root CA (do not use in production!)
  - localhost as common name
- Add new issuing CA
  - CA type: Local issuing CA, Import method: Import issuing CA from file
  - use PEM format
  - select the keys and certs from tests/data/rsa2048, leave password empty
  - Alternatively, generate CA from local root CA
- Add Endpoint profile
  - add unique name and select an issuing CA from dropdown
- Add new device
  - Set device name
  - Select onboarding protocol: Trustpoint Client
  - Select the endpoint profile as previously added
- Start onboarding using the [Trustpoint Client](https://github.com/TrustPoint-Project/trustpoint-client)
  - copy the command by the trustpoint server frontend
  - run the command in trustpoint-client folder. It should give an output similar to the following:
  ```
  Provisioning client...
  Current system time is 2024-04-16T14:50:58Z
  Retrieving Trustpoint Trust Store
  trust-store.pem missing, downloading from Trustpoint...
  Using PBKDF2-HMAC verification
  Computed PBKDF2-key: 5195651ac62207f15b3425bf7a7cef919a5be5499abf02c258b82b107d740da4
  Computed HMAC: af92597d792de750f0a3b7f89e78895659fd646fde760f9047288098cd3da75a
  Thank you, the trust store was downloaded successfully.
  Generating private key and CSR for LDevID
  Device Serial number: tpclient_3DIhO3zuhH6KDrBu
  Uploading CSR to Trustpoint for signing
  LDevID certificate downloaded successfully
  Cert expires 2025-04-16 14:50:58+00:00, 364 days, 23:59:59 h from now.
  Downloading LDevID certificate chain
  Certificate chain downloaded successfully
  Successfully provisioned the Trustpoint-Client.
  ```
  - on trustpoint frontend device onboarding status will turned to `ok`
