"""Models for the users application."""

import secrets

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

TOKEN_BYTES = 32

def unique_token():
    for _ in range(10):
        token = secrets.token_urlsafe(TOKEN_BYTES)
        if not PersonalAccessToken.objects.filter(token=token).exists():
            return token
    raise ValueError('Too many attempts to generate the token')

def expiration():
    return timezone.now() + timezone.timedelta(days=365)

class PersonalAccessToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=TOKEN_BYTES*2,default=unique_token,editable=False,unique=True)
    expiration = models.DateTimeField(default=expiration)

    def get_user(provided_token:str):
        tk = PersonalAccessToken.objects.filter(token=provided_token).last()
        if tk and tk.expiration > timezone.now():
            return tk.user
        return None

    def get_from_string(provided_token:str):
        return PersonalAccessToken.objects.filter(token=provided_token).last()

    def __str__(self):
        return f'{self.token} ({self.user.username})'
