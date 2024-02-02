# trustpoint

## Installation

You should create a virtual pip environment and install the dependencies within it.

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Make sure to run all following commands within the virtual env. You can always enter it through **source .venv/bin/activate**
in the top directory of our trustpoint project. To leave it use **deactivate**.

(.venv) should be displayed in the beginning of the cli prompt to indicate that you are indeed within the virtual env.

### Setting up the DB and SuperUser

Firstly, we need to create a sqlite database for development, migrate / create the required tables and create
a superuser.  The superuser credentials can later be used to access the admin page: localhost:8000/admin/.

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

#### Running the development server

```bash
python manage.py runserver
```

You can then access the GUI through localhost:8000.

