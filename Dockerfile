FROM debian:bookworm-slim
# This will not work, since debian uses a slightly different apache2 config structure.
# Current Dockerfile is meant to be used with the ubuntu apache2 setup.
# FROM python:3.12.2-slim-bookworm

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443

RUN apt update -y && apt install -y sudo apt-utils apache2 apache2-utils python3 python3-venv libapache2-mod-wsgi-py3 python3-pip

RUN a2enmod ssl
RUN a2enmod rewrite

RUN ln /usr/bin/python3 /usr/bin/python

# Install poetry
ENV POETRY_HOME=/opt/poetry
RUN python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install poetry==1.8.2

# Copy the current directory contents into the container
COPY ./ /var/www/html/trustpoint/

WORKDIR /var/www/html/trustpoint/

# Install dependencies (we do not need venv in the container)
RUN $POETRY_HOME/bin/poetry config virtualenvs.create false && $POETRY_HOME/bin/poetry install --no-interaction 

# Change owner and group
#RUN chown -R www-data:www-data .

# change permission for db file
#RUN chmod 664 db.sqlite3

# reset database
RUN yes | python trustpoint/manage.py reset_db --no-user


# collect static files
RUN python trustpoint/manage.py collectstatic --noinput


# Change owner and group
#RUN chown -R www-data:www-data .


# Generate self-signed certificates
#RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
# -keyout /etc/ssl/private/apache-selfsigned.key \
#  -out /etc/ssl/certs/apache-selfsigned.crt  \
#    -subj "/C=DE/ST=BW/L=Stuttgart/O=Trustpoint/OU=Trustpoint/CN=localhost"

RUN mkdir /etc/trustpoint/

COPY ./docker/ /etc/trustpoint/

RUN chown -R root:root /etc/trustpoint/
RUN chmod -R 755 /etc/trustpoint/

ADD ./docker/wizard/sudoers /etc/sudoers
RUN chown root:root /etc/sudoers
RUN chmod 440 /etc/sudoers

RUN service sudo restart

RUN rm /etc/apache2/sites-enabled/*
# Copy Apache configuration
ADD ./docker/apache/trustpoint-http-init.conf /etc/apache2/sites-available/trustpoint-http-init.conf
#ADD ./trustpoint-apache-https.conf /etc/apache2/sites-available/localhost.conf

# Change owner and group
RUN chown -R www-data:www-data .

# Enable the site configuration
RUN a2ensite trustpoint-http-init.conf

#RUN a2ensite localhost.conf

# RUN apache as www-data user and in foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
