FROM ubuntu
#FROM python:3.12.2-slim-bookworm

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y \
    apt-utils vim curl apache2 apache2-utils \
    python3 libapache2-mod-wsgi-py3

RUN ln /usr/bin/python3 /usr/bin/python
RUN apt-get -y install python3-pip python3-venv

# Install poetry
ENV POETRY_HOME=/opt/poetry
RUN python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install poetry==1.8.2

# Copy the current directory contents into the container
COPY ./ /var/www/html/trustpoint/

# Set the working directory in the container
WORKDIR /var/www/html/trustpoint/

# Change owner and group
RUN chown -R www-data:www-data .

# Install dependencies (we do not need venv in the container)
RUN $POETRY_HOME/bin/poetry config virtualenvs.create false && $POETRY_HOME/bin/poetry install --no-interaction 

WORKDIR /var/www/html/trustpoint/trustpoint

#RUN chown www-data:www-data db.sqlite3
RUN chmod 664 db.sqlite3

# Run Django migrations and create superuser
RUN python manage.py makemigrations && python manage.py migrate

# After running migrations, add the following to create a superuser
# Set environment variables for superuser creation
ENV DJANGO_SUPERUSER_USERNAME=testadmin \
    DJANGO_SUPERUSER_PASSWORD=testadmin321 \
    DJANGO_SUPERUSER_EMAIL=testadmin@example.com
    
RUN echo "from django.contrib.auth import get_user_model; \
  User = get_user_model(); \
  User.objects.create_superuser( \
    '$DJANGO_SUPERUSER_USERNAME', \
    '$DJANGO_SUPERUSER_EMAIL', \
    '$DJANGO_SUPERUSER_PASSWORD'\
  )" | python manage.py shell

# Copy Apache configuration
ADD ./trustpoint.conf /etc/apache2/sites-available/000-default.conf

# Make port 80 available to the world outside this container
EXPOSE 80

# Run development server with HTTPS when the container launches
# CMD python manage.py runserver_plus 0.0.0.0:8000 --cert-file ../tests/data/x509/https_server.crt --key-file ../tests/data/x509/https_server.pem
# CMD ["python", "manage.py", "runserver_plus", "8000", "--cert-file", "../tests/data/x509/https_server.crt", "--key-file", "../tests/data/x509/https_server.pem"]
# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Run Apache in the foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
