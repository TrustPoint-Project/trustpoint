"""This module contains models for the Onboarding app."""

from django.db import models
from devices.models import Device
import secrets
from .cryptoBackend import CryptoBackend as Crypt
from enum import IntEnum
import threading

onboardingTimeout = 1800  # seconds, TODO: add to configuration


class OnboardingProcessState(IntEnum):
    """Enum representing the state of an onboarding process.
    
    Negative values indicate an error state.
    """
    NO_SUCH_PROCESS = -2
    FAILED = -1
    STARTED = 0
    HMAC_GENERATED = 1
    TRUST_STORE_SENT = 2
    CSR_RECEIVED = 3
    DEVICE_VALIDATED = 4
    LDEVID_SENT = 5
    COMPLETED = 6  # aka cert chain was requested


# NOT a database-backed model
class OnboardingProcess:
    """Represents an onboarding process for a device.
    
    This model is not written to the database.
    We may consider restructuring this in the future to write some of the values, e.g. for logging purposes.
    """

    id_counter = 1  # only unique within the current server runtime

    def __init__(self, dev):
        """ Initializes a new onboarding process for a device. 
        
        Generates secrets, starts two threads for trust store HMAC generation and a timer for timeout.
        """
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.url = secrets.token_urlsafe(4)
        self.otp = secrets.token_hex(8)
        self.tsotp = secrets.token_hex(8)
        self.salt = secrets.token_hex(8)
        self.tssalt = secrets.token_hex(8)
        self.hmac = None
        self.state = OnboardingProcessState.STARTED
        self.error_reason = ''
        self.gen_thread = threading.Thread(target=self.calc_hmac)
        self.gen_thread.start()
        self.timer = threading.Timer(onboardingTimeout, self.timeout)
        self.timer.start()
        self.active = True
        OnboardingProcess.id_counter += 1

    def __str__(self):
        return 'OnboardingProcess {} for device {}'.format(self.id, self.device.name)

    def __repr__(self):
        return self.__str__()

    def get_by_id(id):
        for process in onboardingProcesses:
            if process.id == id:
                return process
        return None

    def get_by_url_ext(url):
        for process in onboardingProcesses:
            if process.url == url:
                return process
        return None
    
    def fail(self, reason=''):
        """Cancels the onboarding process with a given reason."""

        self.state = OnboardingProcessState.FAILED
        self.active = False
        self.error_reason = reason

    def calc_hmac(self):
        """Calculates the HMAC signature of the trust store.
        
        Runs in separate gen_thread thread started by __init__ as it typically takes about a second.
        """	

        try:
            self.hmac = Crypt.pbkdf2_hmac_sha256(self.tsotp, self.tssalt, Crypt.get_trust_store().encode('utf-8'))
        except Exception as e:
            self.fail('Error generating trust store HMAC.')
            raise Exception('Error generating trust store HMAC.') from e

        if self.state == OnboardingProcessState.STARTED:
            self.state = OnboardingProcessState.HMAC_GENERATED

    def get_hmac(self):
        """Returns the HMAC signature of the trust store and the PBKDF2 of the trust store OTP and salt."""
        self.gen_thread.join()
        return self.hmac

    def check_ldevid_auth(self, uname, passwd):
        if not self.active:
            return False
        if uname == self.salt and passwd == self.otp:
            self.state = OnboardingProcessState.DEVICE_VALIDATED
            return True
        else:
            self.fail('Client provided invalid credentials.')
        return False

    def sign_ldevid(self, csr):
        if not self.active:
            return None
        if self.state != OnboardingProcessState.DEVICE_VALIDATED:
            return None
        try:
            ldevid = Crypt.sign_ldevid(csr, self.device)
        except Exception as e:
            self.fail(str(e))  # TODO: is it safe to print exception messages to the user UI?
            raise
        if ldevid:
            self.state = OnboardingProcessState.LDEVID_SENT
        else:
            self.fail('No LDevID was generated.')
        return ldevid

    def timeout(self):
        self.fail('Process timed out.')

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)


onboardingProcesses = []
