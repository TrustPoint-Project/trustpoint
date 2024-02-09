from django.db import models
from devices.models import Device

# NOT a database-backed model
class OnboardingProcess:
    id_counter = 0
    
    def __init__(self, dev):
        self.device = dev
        self.id = id_counter
        id_counter += 1

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)

onboardingProcesses = []