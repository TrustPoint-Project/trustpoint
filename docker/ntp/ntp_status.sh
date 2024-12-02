#!/bin/bash

# Check if Chrony is running
echo "Checking Chrony status..."

if pgrep chronyd > /dev/null 2>&1; then
    echo "Chrony is running."

    if command -v chronyc > /dev/null 2>&1; then
        echo "Chrony synchronization status:"
        chronyc tracking
    else
        echo "chronyc command is not available to check synchronization status."
    fi
else
    echo "Chrony is not running."
    exit 1
fi
