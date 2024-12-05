#!/bin/bash

CHRONY_CONF="/etc/chrony/chrony.conf"

# Ensure Chrony is installed and available
if ! command -v chronyd &> /dev/null; then
    echo "Chrony is not installed. Please install it first."
    exit 1
fi

if [ ! -f "$CHRONY_CONF" ]; then
    echo "Chrony configuration file not found: $CHRONY_CONF"
    exit 2
fi

# Start Chrony in the background
echo "Starting Chrony in the background..."
nohup chronyd > /var/log/chrony.log 2>&1 &

# Check if the process started successfully
if pgrep chronyd > /dev/null; then
    echo "Chrony started successfully."
    exit 0
else
    echo "Failed to start Chrony."
    exit 3
fi