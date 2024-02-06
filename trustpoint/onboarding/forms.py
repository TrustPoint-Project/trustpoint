from django import forms

class OnboardingStartForm(forms.Form):
    name = forms.CharField(label='Device Name', max_length=32, required=True)