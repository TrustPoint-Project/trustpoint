from django.db import models
from devices.models import Device
from .cryptoBackend import CryptoBackend as crypt

# NOT a database-backed model
class OnboardingProcess:
    id_counter = 1 # not stored in DB, so it doesn't matter that it resets on restart. However, we might consider storing OnboardingProcesses in DB anyways for logging purposes

    def __init__(self, dev):
        self.device = dev
        self.id = OnboardingProcess.id_counter
        self.url = crypt.random_character_string(6)
        OnboardingProcess.id_counter += 1

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)

onboardingProcesses = []