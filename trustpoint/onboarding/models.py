from django.db import models
from devices.models import Device
import secrets

# NOT a database-backed model
class OnboardingProcess:
    id_counter = 1 # not stored in DB, so it doesn't matter that it resets on restart. However, we might consider storing OnboardingProcesses in DB anyways for logging purposes

    def __init__(self, dev):
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.url = secrets.token_urlsafe(4)
        self.otp = secrets.token_hex(8)
        self.salt = secrets.token_hex(8)
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

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)

onboardingProcesses = []