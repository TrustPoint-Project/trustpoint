from django.db import models
from devices.models import Device
import secrets
from .cryptoBackend import CryptoBackend as Crypt
from enum import IntEnum
import threading

onboardingTimeout = 1800  # seconds, TODO: add to configuration


class OnboardingProcessState(IntEnum):
    TIMED_OUT = -4
    INCORRECT_OTP = -3
    NO_SUCH_PROCESS = -2
    FAILED = -1
    STARTED = 0
    HMAC_GENERATED = 1
    TRUST_STORE_SENT = 2
    CSR_RECEIVED = 3
    DEVICE_VALIDATED = 4
    LDEVID_SENT = 5
    COMPLETED = 6

# NOT a database-backed model
class OnboardingProcess:
    # not stored in DB, so it doesn't matter that it resets on restart.
    # However, we might consider storing OnboardingProcesses in DB anyways for logging purposes
    id_counter = 1

    def __init__(self, dev):
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.url = secrets.token_urlsafe(4)
        self.otp = secrets.token_hex(8)
        self.tsotp = secrets.token_hex(8)
        self.salt = secrets.token_hex(8)
        self.tssalt = secrets.token_hex(8)
        self.hmac = None
        self.state = OnboardingProcessState.STARTED
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

    def calc_hmac(self):
        self.hmac = Crypt.pbkdf2_hmac_sha256(self.tsotp, self.tssalt, Crypt.get_trust_store().encode('utf-8'))
        if self.state == OnboardingProcessState.STARTED:
            self.state = OnboardingProcessState.HMAC_GENERATED

    def get_hmac(self):
        self.gen_thread.join()
        return self.hmac

    def check_ldevid_auth(self, uname, passwd):
        if not self.active:
            return False
        if uname == self.salt and passwd == self.otp:
            self.state = OnboardingProcessState.DEVICE_VALIDATED
            return True
        else:
            self.state = OnboardingProcessState.INCORRECT_OTP
            self.active = False
        return False
    
    def sign_ldevid(self, csr):
        if not self.active: return None
        if (self.state != OnboardingProcessState.DEVICE_VALIDATED):
            return None
        ldevid = Crypt.sign_ldevid(csr, self.device)
        if ldevid:
            self.state = OnboardingProcessState.LDEVID_SENT
        else:
            self.state = OnboardingProcessState.FAILED
            self.active = False
        return ldevid
    
    def timeout(self):
        self.state = OnboardingProcessState.TIMED_OUT
        self.active = False

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)


onboardingProcesses = []
