#!/bin/bash

# Stop Chrony
echo "Stopping Chrony..."
pkill chronyd

if [ $? -eq 0 ]; then
    echo "Chrony stopped successfully."
else
    echo "Failed to stop Chrony or it wasn't running."
    exit 1
fi
