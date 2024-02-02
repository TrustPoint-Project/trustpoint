from django.shortcuts import redirect


def dashboard(request):
    return redirect('home-dashboard')
