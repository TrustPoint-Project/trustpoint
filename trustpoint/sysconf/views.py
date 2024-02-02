from django.shortcuts import render, redirect


def index(request):
    return redirect('sysconf-logging')


# Create your views here.
def logging(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'logging'
    }
    return render(request, 'sysconf/logging.html', context=context)


def network(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'network'
    }
    return render(request, 'sysconf/network.html', context=context)


def ntp(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'ntp'
    }
    return render(request, 'sysconf/ntp.html', context=context)


def ssh(request):
    context = {
        'page_category': 'sysconf',
        'page_name': 'ssh'
    }
    return render(request, 'sysconf/ssh.html', context=context)
