Trustpoint Development environment setup
========================================

Installation
------------

| The current version uses a Python Django framework.
| We are using pyenv and poetry to manage different python versions and
  dependencies.

Please note that the current version is in **development status** and
still subject to **major changes**. Our aim is to make an operational
version of the software available quickly in order to receive as much
feedback as possible from users.

Pyenv
~~~~~

| [OPTIONAL] You can use pyenv to install and manage different Python
  versions in parallel.
| To install it, install all `required build
  dependencies <https://github.com/pyenv/pyenv/wiki#suggested-build-environment>`__.

Then follow the `installation
manual <https://github.com/pyenv/pyenv?tab=readme-ov-file#installation>`__.

You can add the following to your .bashrc:

.. code:: shell

   export PATH="$PATH:/home/<your-user-name>/.pyenv/bin/"

   export PYENV_ROOT="$HOME/.pyenv"
   [[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
   eval "$(pyenv init -)"

Restart your shell

.. code:: shell

   exec "$SHELL"

You can install the desired python version as follows

.. code:: shell

   pyenv install 3.12.2
   pyenv global 3.12.2

Poetry
~~~~~~

| You should use poetry to create a virtual environment and to manage
  the dependencies (instead of pip directly).
| The easiest way to install poetry is their offered
  `installer <https://python-poetry.org/docs/#installing-with-the-official-installer>`__

You can also follow the manual steps, without just executing a
downloaded script (security wise, the better decision).

You can add the following to your .bashrc

.. code:: shell

   export PATH="$PATH:/home/<your-user-name>/.local/bin/"

To configure the python environment, see `the Poetry documentation on
managing
environments <https://python-poetry.org/docs/managing-environments/>`__

If you are using pyenv, make sure to add the following configuration:

.. code:: shell

   poetry config virtualenvs.prefer-active-python true

.. _install-dependencies-with-poetry:

Install dependencies with poetry.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have an existing virtual environment, e.g. through using python3
-m venv, exit the virtual environment (that is make sure you are not in
the environment). You can usually exit it with:

.. code:: shell

   deactivate

Then, remove any virtual environment you may have set up, e.g. .venv/
directory.

Finally, install everything through poetry:

.. code:: shell

   cd /path/to/trustpoint/
   poetry install

Activating the environment
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: shell

   poetry shell

You can now use the manage.py file as usual.

Setting up the DB and SuperUser
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Firstly, we need to create a sqlite database for development, migrate /
create the required tables and create a superuser. The superuser
credentials ``admin``/``testing321`` can later be used to access the
admin page: localhost:8000/admin/.

.. code:: bash

   cd trustpoint
   python manage.py reset_db

Use any database client to connect to the database. you need to
configure two settings

-  database type : SQLite
-  database file path: path to ``db.sqlite3`` file in trustpoint folder

Running the development server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   python manage.py runserver

You can then access the GUI through localhost:8000.

Alternatively, use the following command to run a development HTTPS
server (self-signed certificate).

.. code:: bash

   python manage.py runserver_plus 0.0.0.0:443 --cert-file ../tests/data/x509/https_server.crt --key-file ../tests/data/x509/https_server.pem

Use the following command to automatically generate a self-signed TLS
server certificate for your current IP addresses:

.. code:: bash

   python manage.py create_tls_certs

Logging in
^^^^^^^^^^

Browsing to any page should redirect you to the login page. The login
page can be accessed directly via /users/login/.

Use the username and password which you previously provided through the
**createsuperuser** command.

Management commands for testing and development purposes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   python manage.py reset_db

Clears the database and restores Trustpoint to the initial state.

.. code:: bash

   python manage.py add_domains_and_devices

Populates the database with an example CA, domain and device instances.

.. code:: bash

   python manage.py makemsg -l de
   python manage.py makemsg -l de -d djangojs

Makes the translation (.po) files from translatable strings. gettext
must be installed on your system.

.. code:: bash

   python manage.py compilemsg

Compiles the translation files (.po) to binary (.mo) files actually used
by Django.

Building auto documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   cd ../docs
   sphinx-apidoc -f -e -o ./source ../trustpoint /*/migrations/*
   make html

Adding dependencies to the project
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Dependencies generally required for the project can be added using the
following:

.. code:: shell

   poetry add <name-of-package>

Dependencies that are only required in development, use the following to
add in within the dev section:

.. code:: shell

   poetry add --group=dev <name-of-package>

Using the ruff linter and formatter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For linting everything in the current directory use:

.. code:: shell

   ruff check .

For active formatting everything in the current directory use:

.. code:: shell

   ruff format .
