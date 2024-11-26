FROM ubuntu
# This will not work, since debian uses a slightly different apache2 config structure.
# Current Dockerfile is meant to be used with the ubuntu apache2 setup.
# FROM python:3.12.2-slim-bookworm

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443

RUN apt-get update && apt-get install -y apt-utils vim curl apache2 apache2-utils gettext python3 libapache2-mod-wsgi-py3 python3-pip python3-venv

RUN a2enmod ssl
RUN a2enmod rewrite

RUN ln /usr/bin/python3 /usr/bin/python

# Install poetry
ENV POETRY_HOME=/opt/poetry
RUN python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install poetry==1.8.2

# Copy the current directory contents into the container
COPY ./ /var/www/html/trustpoint/

# Set the working directory in the container
WORKDIR /var/www/html/trustpoint/

# Install dependencies (we do not need venv in the container)
RUN $POETRY_HOME/bin/poetry config virtualenvs.create false && $POETRY_HOME/bin/poetry install --no-interaction 

WORKDIR /var/www/html/trustpoint/trustpoint

# reset database
RUN yes | python manage.py reset_db

# change permission for db file
RUN chmod 664 db.sqlite3

# collect static files
RUN python manage.py collectstatic --noinput

# compile messages (translations)
RUN python manage.py compilemessages

# Change owner and group
RUN chown -R www-data:www-data .

# Generate self-signed certificates
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout /etc/ssl/private/apache-selfsigned.key \
  -out /etc/ssl/certs/apache-selfsigned.crt  \
    -subj "/C=DE/ST=BW/L=Stuttgart/O=Trustpoint/OU=Trustpoint/CN=localhost"


# Copy Apache configuration
ADD ./trustpoint-apache-http.conf /etc/apache2/sites-available/000-default.conf
ADD ./trustpoint-apache-https.conf /etc/apache2/sites-available/localhost.conf

# Enable the site configuration
RUN a2ensite localhost.conf

## Run Apache in the foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
