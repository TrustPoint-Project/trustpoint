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

if [ -f "$CHRONY_CONF" ]; then
  cp "$CHRONY_CONF" "$BACKUP_CONF"
else
  echo "/etc/chrony/chrony.conf does not exist, skipping..."
fi

# Update configuration
echo "Updating Chrony configuration with server $SERVER and port $PORT..."
cat <<EOL > "$CHRONY_CONF"
# Updated Chrony configuration
server $SERVER iburst port $PORT

# The rtcsync directive enables a mode where the system time is periodically copied to the RTC
# Disable this temporarily during major offsets
# rtcsync

# Allow stepping the system clock for larger offsets
makestep 86400 10

# Allow NTP client requests from localhost only
allow 127.0.0.1

# Drift file
driftfile /var/lib/chrony/chrony.drift

# Log files
logdir /var/log/chrony
EOL

echo "Chrony configuration updated successfully."

