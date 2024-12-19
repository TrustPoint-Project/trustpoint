==========================
Poetry Setup Instructions
==========================

This guide outlines the steps to set up the project environment, manage dependencies with Poetry, configure the database, and run the development server.

--------------------------
1. Install Poetry
--------------------------

The easiest way to install poetry is their offered `installer <https://python-poetry.org/docs/#installing-with-the-official-installer>`_.

Add Poetry to your PATH by updating your shell configuration file:

- For Bash users:

  .. code-block:: bash

      echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
      source ~/.bashrc

- For Zsh users:

  .. code-block:: bash

      echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.zshrc
      source ~/.zshrc

-----------------------------------
2. Install Dependencies with Poetry
-----------------------------------

Navigate to your project directory and install dependencies using Poetry:

.. code-block:: bash

    cd /path/to/trustpoint/
    poetry install

This command will:
- Install all dependencies listed in `pyproject.toml`.
- Create a virtual environment under `.venv` or as per Poetry's configuration.

---------------------------
3. Activate the Environment
---------------------------

Activate the Poetry-managed virtual environment:

.. code-block:: bash

    poetry shell

Your terminal prompt will reflect the activated environment.

------------------------------------
4. Set Up the Database and Superuser
------------------------------------

To set up the SQLite database for development:

1. **Navigate to the project directory**:

   .. code-block:: bash

       cd trustpoint

2. **Make and apply migrations**:

   .. code-block:: bash

       python manage.py makemigrations
       python manage.py migrate

3. **Create a superuser** to access the admin interface:

   .. code-block:: bash

       python manage.py createsuperuser

   Follow the prompts to set a username, and password.

-----------------------------
5. Run the Development Server
-----------------------------

To start the development server, run the server over HTTP with:

.. code-block:: bash

  python manage.py runserver


Access the GUI at: `http://localhost:8000`.




