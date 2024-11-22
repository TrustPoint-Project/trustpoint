#!/bin/bash
# This script will transition the from the WIZARD_INITIAL state to the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
APACHE_TLS_DIRECTORY="/etc/trustpoint/tls/"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
WIZARD_DEMO_DATA="/etc/trustpoint/wizard/state/WIZARD_DEMO_DATA"

# Checks if the state file is present.
if [ ! -f "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY" ]; then
    echo "Trustpoint is not in the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "Found multiple wizard state files. The wizard state seems to be corrupted."
    exit 2
fi

# Makes sure the apache2 directory exists.
if ! mkdir -p "$APACHE_TLS_DIRECTORY"
then
    echo "Failed to create the required tls directory for the apache TLS-Server credential."
    exit 3
fi

# Makes sure the apache2 tls directory does not contain any files or directories.
if ! rm -f /etc/trustpoint/tls/*
then
    echo "The directory that holds the apache TLS-Server credential contains unexpected elements."
    exit 4
fi

# Copies the TLS-Server credentials into the apache2 TLS directory.
if ! cp /var/www/html/trustpoint/docker/apache/tls/* "$APACHE_TLS_DIRECTORY"
then
    echo "Failed to copy Trustpoint TLS files for the apache configuration."
    exit 5
fi

# Makes sure no other sites are enabled within the apache2
if ! rm -f /etc/apache2/sites-enabled/*
then
    echo "There are sites in apache2 enabled, that could not be removed."
    exit 6
fi

# Copies the apache http (80) config into site-available.
if ! cp /var/www/html/trustpoint/docker/apache/trustpoint-apache-http.conf /etc/apache2/sites-available/trustpoint-apache-http.conf
then
    echo "Failed to copy trustpoint-apache-http.conf into apache2 sites-available."
    exit 7
fi

# Copies the apache http (80) config into site-enabled.
if ! cp /var/www/html/trustpoint/docker/apache/trustpoint-apache-http.conf /etc/apache2/sites-enabled/trustpoint-apache-http.conf
then
    echo "Failed to copy trustpoint-apache-http.conf into apache2 sites-available."
    exit 8
fi

# Copies the apache https (443) config into site-available.
if ! cp /var/www/html/trustpoint/docker/apache/trustpoint-apache-https.conf /etc/apache2/sites-available/trustpoint-apache-https.conf
then
    echo "Failed to copy trustpoint-apache-http.conf into apache2 sites-available."
    exit 9
fi

# Copies the apache https (443) config into site-enabled.
if ! cp /var/www/html/trustpoint/docker/apache/trustpoint-apache-https.conf /etc/apache2/sites-enabled/trustpoint-apache-https.conf
then
    echo "Failed to copy trustpoint-apache-http.conf into apache2 sites-available."
    exit 10
fi

# Tries to gracefully restart and reload the apache2 webserver.
if ! apache2ctl graceful
then
    echo "Failed to gracefully restart and reload the apache2 webserver."
    exit 11
fi

# Removes the current WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.
if ! rm "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
then
    echo "Failed to remove the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 12
fi

# Creates the WIZARD_DEMO_DATA state file.
if ! touch "$WIZARD_DEMO_DATA"
then
    echo "Failed to create WIZARD_DEMO_DATA state file."
    exit 13
fi
