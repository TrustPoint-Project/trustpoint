#!/bin/bash
set -e  # Exit on error

run_as_www_data() {
  su -s /bin/bash www-data -c "$1"
}

# Wait for the database to be ready (only for PostgreSQL)
if [ "$DATABASE_ENGINE" == "django.db.backends.postgresql" ]; then
  echo "Waiting for PostgreSQL database..."
  while ! (echo > /dev/tcp/"$DATABASE_HOST"/"$DATABASE_PORT") &>/dev/null; do
    sleep 1
  done
  echo "PostgreSQL database is available!"
fi

# Reset the database
echo "Resetting the database..."
run_as_www_data "python trustpoint/manage.py reset_db --no-user --force"
echo "Database resetted."

# Collect static files
echo "Collecting static files..."
run_as_www_data "python trustpoint/manage.py collectstatic --noinput"
echo "Static files collected."

# Compile messages (translations)
echo "Compiling Messages..."
run_as_www_data "python trustpoint/manage.py compilemessages"
echo "Messages compiled."

# Start Apache server
echo "Starting Apache server..."
exec apache2ctl -D FOREGROUND
