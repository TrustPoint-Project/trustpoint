"""This module contains models for the Onboarding app."""

from __future__ import annotations

import secrets
import logging
import threading
from enum import IntEnum
from typing import TYPE_CHECKING

from devices.models import Device
from django.db import models

from onboarding.crypto_backend import CryptoBackend as Crypt
from onboarding.crypto_backend import OnboardingError

if TYPE_CHECKING:
    from typing import TypeVar

onboarding_timeout = 1800  # seconds, TODO: add to configuration

log = logging.getLogger('tp.onboarding')

class OnboardingProcessState(IntEnum):
    """Enum representing the state of an onboarding process.

    Negative values indicate an error state.
    """

    NO_SUCH_PROCESS = -3
    CANCELED = -2
    FAILED = -1
    STARTED = 0
    HMAC_GENERATED = 1
    TRUST_STORE_SENT = 2
    DEVICE_VALIDATED = 3
    LDEVID_SENT = 4
    COMPLETED = 5  # aka cert chain was requested


class NoOnboardingProcessError(Exception):
    """Exception raised when no onboarding process is found for a certain device, ID, or url extension."""

    def __init__(self, message: str = 'No onboarding process found.') -> None:
        """Initializes a new NoOnboardingProcessError with a given message."""
        self.message = message
        super().__init__(self.message)

# NOT a database-backed model
class OnboardingProcess:
    """Represents an onboarding process for a device.

    This model is not written to the database.
    We may consider restructuring this in the future to write some of the values, e.g. for logging purposes.
    """

    id_counter = 1  # only unique within the current server runtime

    def __init__(self, dev: Device) -> None:
        """Initializes a new onboarding process for a device.

        Generates secrets, starts two threads for trust store HMAC generation and a timer for timeout.
        """
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.state = OnboardingProcessState.STARTED
        self.error_reason = ''
        self.url = secrets.token_urlsafe(4)
        self.timer = threading.Timer(onboarding_timeout, self._timeout)
        # TODO (Air): instead of daemon, consider using events to exit gracefully on shutdown
        self.timer.daemon = True
        self.timer.start()
        self.active = True
        OnboardingProcess.id_counter += 1
        log.info(f'Onboarding process {self.id} started for device {self.device.device_name}.')

    def __str__(self) -> str:
        """Returns the onboarding process in human-readable format."""
        return f'OnboardingProcess {self.id} for device {self.device.device_name}'

    def __repr__(self) -> str:
        """Returns the onboarding process in human-readable format."""
        return self.__str__()

    @staticmethod
    def get_by_id(process_id: int) -> OnboardingProcess | None:
        """Returns the onboarding process with a given ID."""
        for process in onboarding_processes:
            if process.id == process_id:
                return process
        return None

    @staticmethod
    def get_by_url_ext(url: str) -> OnboardingProcess | None:
        """Returns the onboarding process with a given URL extension."""
        for process in onboarding_processes:
            if process.url == url:
                return process
        return None

    @staticmethod
    def get_by_device(device: Device) -> OnboardingProcess | None:
        """Returns the onboarding process for a given device."""
        for process in onboarding_processes:
            if process.device == device:
                return process
        return None

    if TYPE_CHECKING:
        OnboardingProcessTypes = TypeVar('OnboardingProcessTypes', bound='OnboardingProcess')
    @staticmethod
    def make_onboarding_process(device: Device, process_type: type[OnboardingProcessTypes]) -> OnboardingProcessTypes:
        """Returns the onboarding process for the device, creates a new one if it does not exist.

        Args:
            device (Device): The device to create the onboarding process for.
            process_type (classname): The (class) type of the onboarding process to create.

        Returns:
            OnboardingProcessTypes: The onboarding process instance for the device.
        """
        # check if onboarding process for this device already exists
        onboarding_process = OnboardingProcess.get_by_device(device)

        if not onboarding_process:
            onboarding_process = process_type(device)
            onboarding_processes.append(onboarding_process)
            device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDING_RUNNING
            # TODO(Air): very unnecessary save required to update onboarding status in table
            # Problem: if server is restarted during onboarding, status is stuck at running
            device.save()

        return onboarding_process

    @staticmethod
    def cancel_for_device(device: Device) -> tuple[OnboardingProcessState, OnboardingProcess | None]:
        """Cancels the onboarding process for a given device."""
        process = OnboardingProcess.get_by_device(device)
        if process:
            return process.cancel()
        if device and device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
            device.revoke_ldevid()
            device.save()
            log.info(f'Request to cancel non-existing onboarding process for device {device.device_name}.')
            return (OnboardingProcessState.CANCELED, None)

        return (OnboardingProcessState.NO_SUCH_PROCESS, None)

    def cancel(self) -> tuple[OnboardingProcessState, OnboardingProcess]:
        """Cancels the onboarding process and removes it from the list."""
        self.active = False
        self.timer.cancel()
        onboarding_processes.remove(self)
        if self.device and self.device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            # actual cancellation (cancel() may be called just to remove the process from onboarding_processes)
            self.device.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
            self.device.revoke_ldevid()
            self.device.save()
            self.state = OnboardingProcessState.CANCELED
            log.info(f'Onboarding process {self.id} for device {self.device.device_name} canceled.')
        else:
            log.info(f'Onboarding process {self.id} removed from list.')

        return (self.state, self)

    def _fail(self, reason: str = '') -> None:
        """Cancels the onboarding process with a given reason."""
        self.state = OnboardingProcessState.FAILED
        self.active = False
        self.error_reason = reason
        self.timer.cancel()
        self.device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDING_FAILED
        self.device.revoke_ldevid()
        self.device.save()
        log.error(f'Onboarding process {self.id} for device {self.device.device_name} failed: {reason}')

    def _success(self) -> None:
        """Completes the onboarding process."""
        self.state = OnboardingProcessState.COMPLETED
        self.active = False
        self.timer.cancel()
        self.device.device_onboarding_status = Device.DeviceOnboardingStatus.ONBOARDED
        self.device.save()
        log.info(f'Onboarding process {self.id} for device {self.device.device_name} completed.')

    def _timeout(self) -> None:
        """Cancels the onboarding process due to timeout, called by timer thread."""
        self._fail('Process timed out.')

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)


class ManualOnboardingProcess(OnboardingProcess):
    """Onboarding process for a device using the full manual onboarding with OTP and HMAC trust store verification."""

    def __init__(self, dev: Device) -> None:
        """Initializes a new manual onboarding process for a device."""
        super().__init__(dev)
        self.otp = secrets.token_hex(8)
        self.tsotp = secrets.token_hex(8)
        self.salt = secrets.token_hex(8)
        self.tssalt = secrets.token_hex(8)
        self.gen_thread = threading.Thread(target=self._calc_hmac, daemon=True)
        self.gen_thread.start()
        self.hmac = None

    def _calc_hmac(self) -> None:
        """Calculates the HMAC signature of the trust store.

        Runs in separate gen_thread thread started by __init__ as it typically takes about a second.
        """
        try:
            self.hmac = Crypt.pbkdf2_hmac_sha256(self.tsotp, self.tssalt, Crypt.get_trust_store().encode())
        except Exception as e:  # noqa: BLE001
            msg = 'Error generating trust store HMAC.'
            self._fail(msg)
            raise OnboardingError(msg) from e

        if self.state == OnboardingProcessState.STARTED:
            self.state = OnboardingProcessState.HMAC_GENERATED

    def get_hmac(self) -> str:
        """Returns the HMAC signature of the trust store and the PBKDF2 of the trust store OTP and salt."""
        self.gen_thread.join()
        return self.hmac

    def check_ldevid_auth(self, uname: str, passwd: str) -> bool:
        """Checks the provided credentials against OTP stored in the onboarding process."""
        if not self.active:
            return False
        if uname == self.salt and passwd == self.otp:
            self.state = OnboardingProcessState.DEVICE_VALIDATED
            log.debug(f'Device {self.device.device_name} validated for onboarding process {self.id}.')
            return True

        self._fail('Client provided invalid credentials.')
        return False

    def sign_ldevid(self, csr: bytes) -> bytes | None:
        """Issues LDevID certificate with the onboarding CA based on provided CSR."""
        if not self.active:
            return None
        if self.state != OnboardingProcessState.DEVICE_VALIDATED:
            return None
        try:
            ldevid = Crypt.sign_ldevid_from_csr(csr, self.device)
        except Exception as e:
            self._fail(str(e))  # TODO(Air): is it safe to print exception messages to the user UI?
            raise
        if ldevid:
            self.state = OnboardingProcessState.LDEVID_SENT
            log.info(f'LDevID issued for device {self.device.device_name} in onboarding process {self.id}.')
        else:
            self._fail('No LDevID was generated.')
        return ldevid

    def get_cert_chain(self) -> bytes | None:
        """Returns the certificate chain of the LDevID certificate."""
        if not self.active:
            return None
        if self.state != OnboardingProcessState.LDEVID_SENT:
            return None
        try:
            chain = Crypt.get_cert_chain(self.device)
        except Exception as e:
            self._fail(str(e))
            raise

        self._success()
        return chain


class DownloadOnboardingProcess(OnboardingProcess):
    """Onboarding process for a device using the download onboarding method."""

    def __init__(self, dev: Device) -> None:
        """Initializes a new download onboarding process for a device."""
        super().__init__(dev)
        self.gen_thread = threading.Thread(target=self._gen_keypair_and_ldevid)
        self.gen_thread.start()
        self.pkcs12 = None

    def _gen_keypair_and_ldevid(self) -> None:
        """Generates a keypair and LDevID certificate for the device."""
        try:
            if not self.device.device_serial_number:
                self.device.device_serial_number = 'tpdl_' + secrets.token_urlsafe(12)
            self.pkcs12 = Crypt.gen_keypair_and_ldevid(self.device)
            self.state = OnboardingProcessState.LDEVID_SENT
            log.info(f'LDevID issued for device {self.device.device_name} in onboarding process {self.id}.')
        except Exception as e:  # noqa: BLE001
            msg = 'Error generating device key or LDevID.'
            self._fail(msg)
            raise OnboardingError(msg) from e

    def get_pkcs12(self) -> bytes | None:
        """Returns the keypair and LDevID certificate as PKCS12 serialized bytes and ends the onboarding process."""
        log.debug(f'PKCS12 requested for onboarding process {self.id}.')
        self.gen_thread.join()
        self._success()
        return self.pkcs12


class BrowserOnboardingProcess(OnboardingProcess):
    """Onboarding process for a device using the download onboarding method."""

    def __init__(self, dev: Device) -> None:
        """Initializes a new download onboarding process for a device."""
        super().__init__(dev)
        self.otp = secrets.token_hex(8)
        # self.gen_thread = threading.Thread(target=self._gen_keypair_and_ldevid)
        # self.gen_thread.start()
        # self.pkcs12 = None

    def start_onboarding(self):
        self.gen_thread = threading.Thread(target=self._gen_keypair_and_ldevid)
        self.gen_thread.start()
        self.pkcs12 = None

    def _gen_keypair_and_ldevid(self) -> None:
        """Generates a keypair and LDevID certificate for the device."""
        try:
            if not self.device.device_serial_number:
                self.device.device_serial_number = 'tpdl_' + secrets.token_urlsafe(12)
            self.pkcs12 = Crypt.gen_keypair_and_ldevid(self.device)
            self.state = OnboardingProcessState.LDEVID_SENT
            log.info(f'LDevID issued for device {self.device.device_name} in onboarding process {self.id}.')
        except Exception as e:  # noqa: BLE001
            msg = 'Error generating device key or LDevID.'
            self._fail(msg)
            raise OnboardingError(msg) from e

    def get_pkcs12(self) -> bytes | None:
        """Returns the keypair and LDevID certificate as PKCS12 serialized bytes and ends the onboarding process."""
        log.debug(f'PKCS12 requested for onboarding process {self.id}.')
        self.gen_thread.join()
        self._success()
        return self.pkcs12
    
    def get_pem(self) -> bytes | None:
        """Returns the keypair and LDevID certificate as PKCS12 serialized bytes and ends the onboarding process."""
        log.debug(f'PKCS12 requested for onboarding process {self.id}.')
        self.gen_thread.join()
        self._success()
        return Crypt.convert_pkcs12_to_pem(self.pkcs12)

onboarding_processes = []
