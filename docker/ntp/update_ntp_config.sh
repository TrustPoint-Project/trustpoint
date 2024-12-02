#!/bin/bash

# File paths
CHRONY_CONF="/etc/chrony/chrony.conf"
BACKUP_CONF="/etc/chrony/chrony.conf.bak"

# Check if server and port are provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <server> <port>"
    exit 1
fi

SERVER="$1"
PORT="$2"

# Backup existing configuration
echo "Backing up current Chrony configuration to $BACKUP_CONF..."
cp "$CHRONY_CONF" "$BACKUP_CONF"

# Update configuration
echo "Updating Chrony configuration with server $SERVER and port $PORT..."
cat <<EOL > "$CHRONY_CONF"
# Updated Chrony configuration
server $SERVER iburst port $PORT

# Allow NTP client requests from localhost only
allow 127.0.0.1

# Drift file
driftfile /var/lib/chrony/chrony.drift

# Log files
logdir /var/log/chrony
EOL

echo "Chrony configuration updated successfully."

# Restart Chrony to apply new configuration
systemctl restart chronyd
if [ $? -eq 0 ]; then
    echo "Chrony restarted successfully with the new configuration."
else
    echo "Failed to restart Chrony. Check your configuration."
    exit 1
fi
