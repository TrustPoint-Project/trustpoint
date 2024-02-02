from django.shortcuts import render, redirect


def home(request):
    return redirect('home-dashboard')


def home_dashboard(request):
    context = {
        'page_category': 'home',
        'page_name': 'dashboard'
    }
    return render(request, 'home/dashboard.html', context=context)
