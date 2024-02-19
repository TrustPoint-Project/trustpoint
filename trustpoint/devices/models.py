from django.db import models
from django.utils import timezone

# Create your models here.
class Device(models.Model):
  name = models.CharField(max_length=100)
  serial_number = models.CharField(max_length=100, default='')
  certificate = models.FileField(blank=True)
  created_at = models.DateTimeField(default=timezone.now)

  def __str__(self):
    return self.name