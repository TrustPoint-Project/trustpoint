#FROM python:3.12.2
FROM python:3.12.2-slim-bookworm

ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install poetry
ENV POETRY_HOME=/opt/poetry
RUN python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install poetry==1.8.2

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies (we do not need venv in the container)
RUN $POETRY_HOME/bin/poetry config virtualenvs.create false && $POETRY_HOME/bin/poetry install --no-interaction

# Set the working directory to the trustpoint subdirectory
WORKDIR /app/trustpoint

# Run Django migrations and create superuser
RUN python manage.py makemigrations && python manage.py migrate
RUN echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@example.com', 'admin')" | python manage.py shell

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Run development server with HTTPS when the container launches
# CMD python manage.py runserver_plus 0.0.0.0:8000 --cert-file ../tests/data/x509/https_server.crt --key-file ../tests/data/x509/https_server.pem
#CMD ["python", "manage.py", "runserver_plus", "8000", "--cert-file", "../tests/data/x509/https_server.crt", "--key-file", "../tests/data/x509/https_server.pem"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
