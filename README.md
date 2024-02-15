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

## Setting up the DB and SuperUser

Firstly, we need to create a sqlite database for development, migrate / create the required tables and create
a superuser.  The superuser credentials can later be used to access the admin page: localhost:8000/admin/.

```bash
cd trustpoint
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

## Running the development server

```bash
python manage.py runserver
```

You can then access the GUI through localhost:8000.

## Docker

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
docker run -p 8000:8000 your-django-app
```

