#!/bin/bash
set -e  # Exit on error

# Wait for the database to be ready (only for PostgreSQL)
if [ "$DATABASE_ENGINE" == "django.db.backends.postgresql" ]; then
  echo "Waiting for PostgreSQL database..."
  while ! (echo > /dev/tcp/"$DATABASE_HOST"/"$DATABASE_PORT") &>/dev/null; do
    sleep 1
  done
  echo "PostgreSQL database is available!"
fi

# eset the database
echo "Resetting the database..."
uv run trustpoint/manage.py reset_db --no-user --force
echo "Database reseted."

# Collect static files
echo "Collecting static files..."
uv run trustpoint/manage.py collectstatic --noinput
echo "Static files collected."

# Compile messages (translations)
echo "Compiling Messages..."
uv run trustpoint/manage.py compilemessages -l de -l en
echo "Messages compiled."

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
