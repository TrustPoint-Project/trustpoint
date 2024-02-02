from django.shortcuts import render, redirect


def devices(request):
    return redirect('devices-devices')


def devices_devices(request):
    context = {
        'page_category': 'devices',
        'page_name': 'devices'
    }
    return render(request, 'devices/devices.html', context=context)
