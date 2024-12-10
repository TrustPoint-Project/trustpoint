#!/bin/bash

# Ensure Chrony is installed and available
if ! command -v chronyd &> /dev/null; then
    echo "Chrony is not installed. Please install it first."
    exit 1
fi

# Stop Chrony if it's running
echo "Checking if Chrony is running..."
if pgrep -x "chronyd" > /dev/null; then
    echo "Stopping Chrony..."
    pkill -x "chronyd"
    if [ $? -eq 0 ]; then
        echo "Chrony stopped successfully."
    else
        echo "Failed to stop Chrony. Please check if it requires manual intervention."
        exit 2
    fi
else
    echo "Chrony is not running. No need to stop it."
fi

# Start Chrony
echo "Starting Chrony..."
nohup chronyd -d > /var/log/chrony.log 2>&1 &


# Verify if Chrony started successfully
if pgrep -x "chronyd" > /dev/null; then
    echo "Chrony restarted successfully."
    exit 0
else
    echo "Failed to restart Chrony. Check /var/log/chrony.log for more details."
    exit 3
fi
