#!/bin/bash

# Check if Chrony is running
echo "Checking Chrony status..."

if pgrep chronyd > /dev/null 2>&1; then
    echo "Chrony is running."

    if command -v chronyc > /dev/null 2>&1; then
        echo "Chrony synchronization status:"
        OUTPUT=$(chronyc tracking)

        echo "$OUTPUT"

        LEAP_STATUS=$(echo "$OUTPUT" | grep "Leap status" | awk -F': ' '{print $2}')

        case "$LEAP_STATUS" in
            "Normal")
                echo "NTP is working: Leap status is Normal."
                exit 0
                ;;
            "Insert second")
                echo "NTP is working with a scheduled leap second insertion: Leap status is Insert second."
                exit 4
                ;;
            "Delete second")
                echo "NTP is working with a scheduled leap second deletion: Leap status is Delete second."
                exit 5
                ;;
            "Not synchronised")
                echo "NTP is not working: Leap status is Not synchronised."
                exit 3
                ;;
            *)
                echo "Unknown Leap status: $LEAP_STATUS."
                exit 6
                ;;
        esac
    else
        echo "chronyc command is not available to check synchronization status."
        exit 2
    fi
else
    echo "Chrony is not running."
    exit 1
fi