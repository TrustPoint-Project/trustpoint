import subprocess
import socket
import struct
import time
from pathlib import Path

from django.contrib import messages


class NTPStatusChecker:
    """
    A utility class to check the NTP status using a script.
    """

    def __init__(self, script_path):
        self.script_path = Path(script_path)

    def check_status(self):
        """
        Executes the NTP status script and returns the result.
        :return: A tuple (success, message)
                 - success: True if the script executed successfully and NTP is operational.
                 - message: The stdout or stderr from the script.
        """
        if not self.script_path.exists():
            return False, f"Script not found: {self.script_path}"

        try:
            result = subprocess.run(
                ['sudo', str(self.script_path)],
                capture_output=True,
                text=True
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode == 0:
                feedback = ChronyTrackingFeedback(stdout)
                offset_seconds, offset_string = feedback.get_system_time_offset()

                if feedback.is_offset_exceeding():
                    return True, messages.WARNING, f"NTP is working: Leap status is Normal. But the system time offset is {offset_string}. The system clock is gradually adjusted by slightly speeding up or slowing down the clock until it matches the NTP time."

                return True, messages.SUCCESS, f"NTP is working: Leap status is Normal. System time offset is {offset_string}"
            elif result.returncode == 1:
                return False, messages.ERROR, "NTP is not running."
            elif result.returncode == 2:
                return False, messages.ERROR, "Chronyc command is not available for synchronization checks."
            elif result.returncode == 3:
                return False, messages.ERROR, "NTP synchronization failed: Leap status is Not synchronized. Please check your NTP parameters."
            elif result.returncode == 4:
                return True, messages.SUCCESS, "NTP is working with a scheduled leap second insertion: Leap status is Insert second."
            elif result.returncode == 5:
                return True, messages.SUCCESS, "NTP is working with a scheduled leap second deletion: Leap status is Delete second."
            elif result.returncode == 6:
                return False, messages.ERROR, "Unknown Leap status or unexpected error."
            else:
                return False, messages.ERROR, f"Unexpected error with return code {result.returncode}: {stderr or stdout}"

        except Exception as e:
            return False, f"Exception occurred while checking NTP status: {str(e)}"


class NTPRestart:
    """
    A class to handle the execution and management of the Chrony restart script.
    """

    def __init__(self, script_path):
        self.script_path = Path(script_path)

    def restart(self):
        """
        Executes the Chrony restart script and handles its output.
        :return: A tuple (success: bool, message: str)
                 - success: True if the script executes successfully, False otherwise.
                 - message: Script's output or error message.
        """
        if not self.script_path.exists():
            return False, f"Script not found: {self.script_path}"

        try:
            result = subprocess.run(
                ['sudo', str(self.script_path)],
                capture_output=True,
                text=True
            )
            stderr = result.stderr.strip()

            if result.returncode == 0:
                return True, "Restarted NTP"
            elif result.returncode == 1:
                return False, "Chrony is not installed. Please install it first."
            elif result.returncode == 2:
                return False, "Failed to stop Chrony."
            elif result.returncode == 3:
                return False, "Failed to restart Chrony."
            else:
                return False, stderr if stderr else "Unknown error occurred during script execution."
        except Exception as e:
            return False, f"Exception occurred while restarting Chrony: {str(e)}"


class NTPConnectionTester:
    """Class to test the connection to an NTP server."""

    NTP_EPOCH = 2208988800  # Seconds between 1900-01-01 and 1970-01-01

    @staticmethod
    def test_connection(ntp_server: str, server_port: int = 123):
        """
        Test the connection to the specified NTP server.

        Args:
            ntp_server (str): Address of the NTP server.
            server_port (int): Port number (default is 123).

        Returns:
            bool: True if the connection is successful, False otherwise.
            str: Human readable string of the connection status.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)  # Set a timeout for the connection

                # NTP request packet (mode 3, client)
                request_packet = b'\x1b' + 47 * b'\0'

                s.sendto(request_packet, (ntp_server, server_port))
                response, _ = s.recvfrom(1024)
                transmit_timestamp = struct.unpack('!12I', response)[10]
                unix_time = transmit_timestamp - NTPConnectionTester.NTP_EPOCH
                current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(unix_time))

                return True, f"Test Connection successful. Current UTC time: {current_time} for server {ntp_server} and port {server_port} "
        except (socket.timeout, OSError, struct.error):
            return False, f"Test Connection not successful. Could not establish a connection with the server {ntp_server} and port {server_port}."


class ChronyTrackingFeedback:
    def __init__(self, tracking_output):
        """
        Initialize the ChronyTrackingFeedback object with raw tracking output.
        """
        self.raw_output = tracking_output
        self.parsed_data = self._parse_output()

    def _parse_output(self):
        """
        Parse the raw tracking output into a dictionary for easier access.
        """
        parsed = {}
        for line in self.raw_output.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                parsed[key.strip()] = value.strip()
        return parsed

    def get_reference_id(self):
        """Return the Reference ID and the associated NTP server."""
        return self.parsed_data.get('Reference ID')

    def get_stratum(self):
        """Return the stratum level of the NTP server."""
        return int(self.parsed_data.get('Stratum', -1))

    def get_system_time_offset(self):
        """
        Return the system time offset as both a float and a formatted string.
        If parsing fails, return (None, "Error parsing offset").
        """
        offset_str = self.parsed_data.get('System time', '0 seconds')
        try:
            offset_value, direction = offset_str.split()[:2]
            offset_seconds = float(offset_value)
            offset_seconds = offset_seconds if direction == 'slow' else -offset_seconds
            return offset_seconds, offset_str
        except (ValueError, IndexError):
            return None, "Error parsing offset"

    def is_offset_exceeding(self, threshold=2):
        """
        Check if the system time offset exceeds the given threshold in seconds.
        :param threshold: Offset threshold in seconds.
        :return: True if the offset exceeds the threshold, otherwise False.
        """
        offset_seconds, offset_str = self.get_system_time_offset()
        return abs(offset_seconds) > threshold

    def get_rms_offset(self):
        """Return the RMS offset."""
        return float(self.parsed_data.get('RMS offset', '0').split()[0])

    def is_synchronized(self):
        """Determine if the system is synchronized."""
        return self.parsed_data.get('Leap status') == 'Normal'

    def display_summary(self):
        """Display a summary of the synchronization status."""
        ref_id = self.get_reference_id()
        stratum = self.get_stratum()
        offset_float, offset_str = self.get_system_time_offset()
        rms_offset = self.get_rms_offset()
        leap_status = self.is_synchronized()

        summary = (
            f"Reference ID: {ref_id}\n"
            f"Stratum: {stratum}\n"
            f"System Time Offset: {offset_str} "
            f"RMS Offset: {rms_offset} seconds\n"
            f"Leap Status: {'Synchronized' if leap_status else 'Not Synchronized'}"
        )
        print(summary)
