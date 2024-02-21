# Trustpoint


## Installation

We are using pyenv and poetry to manage different python versions and dependencies.


### Pyenv

[OPTIONAL]
You can use pyenv to install and manage different Python versions in parallel.
To install it, install all required build dependencies:

https://github.com/pyenv/pyenv/wiki#suggested-build-environment

Then follow the installation manual:

https://github.com/pyenv/pyenv?tab=readme-ov-file#installation

You can add the following to your .bashrc:

```shell
export PATH="$PATH:/home/<your-user-name>/.pyenv/bin/"

export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```


### Poetry

You should use poetry to create a virtual environment and to manage the dependencies (instead of pip directly).
The easiest way to install poetry is their offered installer.

https://python-poetry.org/docs/#installing-with-the-official-installer

You can also follow the manual steps, without just executing a downloaded script (security wise, the better decision).

You can add the following to your .bashrc

```shell
export PATH="$PATH:/home/<your-user-name>/.local/bin/"
```

To configure the python environment, follow:

https://python-poetry.org/docs/managing-environments/

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
a superuser.  The superuser credentials can later be used to access the admin page: localhost:8000/admin/.

```bash
cd trustpoint
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```


#### Running the development server

```bash
python manage.py runserver
```

You can then access the GUI through localhost:8000.


#### Adding dependencies to the project.

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
   * Open a terminal and navigate to your project's root directory.
   * Run the following command to build the Docker image:
   ```
   docker build -t trustpoint .
   ```

2. Run the Docker container:
   * Once the image is built, you can run a container based on that image:
   ```
   docker run -p 8000:8000 trustpoint
   ```
