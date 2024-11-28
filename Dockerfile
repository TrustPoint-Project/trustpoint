FROM debian:bookworm-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443


# Update apt repository and install required dependencies from apt
RUN apt update -y && apt install -y sudo apt-utils apache2 apache2-utils gettext python3 python3-venv libapache2-mod-wsgi-py3 python3-pip sed

# Create a symbolic link, so that calling python will invoke python3
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install poetry
ENV POETRY_HOME=/opt/poetry
RUN python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install poetry==1.8.2

# Copy the current directory contents into the container
COPY ./ /var/www/html/trustpoint/

# Sets the current WORKDIR for the following commands
WORKDIR /var/www/html/trustpoint/

# Sets DEBUG = False in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py

# Install dependencies (we do not need venv in the container)
RUN $POETRY_HOME/bin/poetry config virtualenvs.create false && $POETRY_HOME/bin/poetry install --no-interaction

# Create and setup the /etc/trustpoint/ directory
RUN mkdir /etc/trustpoint/
COPY ./docker/ /etc/trustpoint/
RUN chown -R root:root /etc/trustpoint/
RUN chmod -R 755 /etc/trustpoint/

# Add sudoers file and configure user and permissions
ADD ./docker/wizard/sudoers /etc/sudoers
RUN chown root:root /etc/sudoers
RUN chmod 440 /etc/sudoers
RUN service sudo restart

# TODO(AlexHx8472): User proper docker secrets handling.
RUN mkdir /etc/trustpoint/secrets
RUN python -c "from pathlib import Path; from django.core.management.utils import get_random_secret_key; secret_key_path = Path('/etc/trustpoint/secrets/django_secret_key.env'); secret_key_path.write_text(get_random_secret_key());"
RUN chown -R www-data:www-data /etc/trustpoint/secrets
RUN chmod -R 700 /etc/trustpoint/secrets

# reset database
RUN yes | python trustpoint/manage.py reset_db --no-user

# collect static files
RUN python trustpoint/manage.py collectstatic --noinput

# compile messages (translations)
RUN python trustpoint/manage.py compilemessages

# Remove any enabled apache2 sites, if any.
RUN rm -f /etc/apache2/sites-enabled/*

# Add Apache configuration
ADD ./docker/apache/trustpoint-http-init.conf /etc/apache2/sites-available/trustpoint-http-init.conf

# Change owner and group
RUN chown -R www-data:www-data .

# Enable the site configuration
RUN a2ensite trustpoint-http-init.conf

# RUN apache as www-data user and in foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
