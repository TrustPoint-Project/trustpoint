FROM ghcr.io/astral-sh/uv:bookworm-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Set the uv cache directory to be in the project directory (owned by www-data user)
ENV UV_CACHE_DIR=/var/www/html/trustpoint/.cache/uv

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443

# Update apt repository and install required dependencies from apt
RUN apt update -y && apt install -y sudo apt-utils apache2 apache2-utils gettext python3 libapache2-mod-wsgi-py3 sed git

# Copy source from current local branch
COPY ./ /var/www/html/trustpoint/
# Alternatively, clone the git repository - main branch
# For git, comment out the above COPY and uncomment the following line:
#RUN git clone https://github.com/TrustPoint-Project/trustpoint.git /var/www/html/trustpoint/

# Sets the current WORKDIR for the following commands
WORKDIR /var/www/html/trustpoint/

#RUN uv sync --frozen
RUN --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project

# Sets DEBUG = False in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py

# Sets DOCKER_CONTAINER = True
RUN sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Place executables in the environment at the front of the path
ENV PATH="/var/www/html/trustpoint/.venv/bin:$PATH"

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

# Remove any enabled apache2 sites, if any.
RUN rm -f /etc/apache2/sites-enabled/*

# Add Apache configuration
ADD ./docker/apache/trustpoint-http-init.conf /etc/apache2/sites-available/trustpoint-http-init.conf

# Change owner and group
RUN chown -R www-data:www-data .

# Enable the site configuration
RUN a2ensite trustpoint-http-init.conf

# Make entrypoint script executable
RUN chmod +x docker/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["docker/entrypoint.sh"]
