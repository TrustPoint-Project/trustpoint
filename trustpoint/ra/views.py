from devices.models import Device
from django.core.files.storage import FileSystemStorage
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views import View
from pki.models import CertificateModel


class OnboardingRequestView(View):
    """View to handle certificate requests and uploads."""
    def get(self, request):
        """Render the form for certificate upload."""
        return render(request, 'onboarding-request.html')

    def post(self, request):
        """Handle certificate file upload and save certificate instance."""
        if request.method == 'POST':
            device_name = request.POST['device_name']
            description = request.POST['description']
            cert_file = request.FILES['cert_file']
            fs = FileSystemStorage()
            filename = fs.save(cert_file.name, cert_file)
            device, created = Device.objects.get_or_create(name=device_name, description=description)
            certificate = CertificateModel(device=device, cert_file=filename)
            certificate.save()
            return HttpResponse('Certificate received and saved.')
        return None

class DownloadCertificateView(View):
    """View to handle certificate download requests."""
    def get(self, request, device_id):
        """Serve the certificate file for the given device."""
        device = get_object_or_404(Device, pk=device_id)
        try:
            certificate = CertificateModel.objects.get(device=device)
            response = HttpResponse(certificate.cert_file, content_type='application/x-pkcs12')
            response['Content-Disposition'] = f'attachment; filename="{device.name}.p12"'
            return response
        except CertificateModel.DoesNotExist:
            raise Http404('Certificate does not exist')
