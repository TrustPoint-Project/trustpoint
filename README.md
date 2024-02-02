# trustpoint

## Installation

You should create a virtual pip environment and install the dependencies within it.

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

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

Then you can access the GUI through localhost:8000.

