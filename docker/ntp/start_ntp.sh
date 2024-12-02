#!/bin/bash

# Ensure Chrony is installed and available
if ! command -v chronyd &> /dev/null; then
    echo "Chrony is not installed. Please install it first."
    exit 1
fi

# Start Chrony
echo "Starting Chrony..."
chronyd -d &  # Run in the background in debug mode (change to normal mode if needed)

if [ $? -eq 0 ]; then
    echo "Chrony started successfully."
else
    echo "Failed to start Chrony."
    exit 1
fi