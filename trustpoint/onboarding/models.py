from django.db import models
from devices.models import Device
import secrets
from  .cryptoBackend import CryptoBackend as Crypt
from enum import IntEnum

class OnboardingProcessState(IntEnum):
    FAILED = -1
    STARTED = 0
    HMAC_GENERATED = 1
    TRUST_STORE_SENT = 2
    CSR_RECEIVED = 3
    DEVICE_VALIDATED = 4
    LDEVID_SENT = 5
    CERT_CHAIN_SENT = 6
    DEVICE_SAVED_TO_DB = 7

# NOT a database-backed model
class OnboardingProcess:
    id_counter = 1 # not stored in DB, so it doesn't matter that it resets on restart. However, we might consider storing OnboardingProcesses in DB anyways for logging purposes

    def __init__(self, dev):
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.url = secrets.token_urlsafe(4)
        self.otp = secrets.token_hex(8)
        self.salt = secrets.token_hex(8)
        self.hmac = None
        self.state = OnboardingProcessState.STARTED
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
        self.hmac = Crypt.pbkdf2_hmac_sha256(self.otp, self.salt, Crypt.get_trust_store().encode('utf-8'))
        if (self.state == OnboardingProcessState.STARTED): self.state = OnboardingProcessState.HMAC_GENERATED
    
    def get_hmac(self):
        if not self.hmac: self.calc_hmac()
        return self.hmac

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)

onboardingProcesses = []