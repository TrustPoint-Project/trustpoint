# add_domains_and_devices.py
import random
import string
from django.core.management.base import BaseCommand
from pki.models import DomainModel
from devices.models import Device

class Command(BaseCommand):
    help = 'Add domains and associated device names with random onboarding protocol and serial number'

    def handle(self, *args, **kwargs):
        data = {
            "arburg": [
                "ALLROUNDER Injection Molding Machine",
                "freeformer 3D Printer",
                "SELOGICA Control System",
                "MULTILIFT Robotic Systems",
                "ARBIDRIVE Servo Motor",
                "ALS (Arburg Leitrechner System)"
            ],
            "homag": [
                "CENTATEQ CNC Processing Center",
                "EDGETEQ Edge Banding Machine",
                "powerTouch Control",
                "intelliGuide Assist System",
                "DRILLTEQ Drilling and Dowel Insertion Machine",
                "STORETEQ Storage System"
            ],
            "belden": [
                "Hirschmann Industrial Ethernet Switches",
                "Lumberg Automation Connectors",
                "GarrettCom Magnum Routers",
                "TROMPETER Coaxial Connectors",
                "Belden I/O Modules"
            ],
            "siemens": [
                "SIMATIC PLC",
                "SINAMICS Drive Systems",
                "SIRIUS Control Devices",
                "SIMOTICS Electric Motors",
                "SIMATIC HMI Panels",
                "SITOP Power Supplies"
            ],
            "phoenix_contact": [
                "CLIPLINE Terminal Blocks",
                "QUINT Power Supplies",
                "PLCnext Control",
                "TERMITRAB Surge Protection",
                "CONTACTRON Motor Starters",
                "ME-PLC Modular Controller"
            ],
            "schmalz": [
                "Vacuum Generators",
                "Vacuum Grippers",
                "Vacuum Clamping Systems",
                "Suction Pads",
                "Vacuum Layer Grippers",
                "Vacuum Ejectors"
            ]
        }

        onboarding_protocols = [protocol.value for protocol in Device.OnboardingProtocol]

        print("Starting the process of adding domains and devices...\n")

        for domain_name, devices in data.items():
            domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)

            if created:
                print(f"Created new domain: {domain_name}")
            else:
                print(f"Domain already exists: {domain_name}")

            print(f"Domain({domain_name}, Issuing CA: {domain.issuing_ca})")

            for device_name in devices:
                onboarding_protocol = random.choice(onboarding_protocols)

                serial_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

                print(f"Creating device '{device_name}' in domain '{domain_name}' with:")
                print(f"  - Serial Number: {serial_number}")
                print(f"  - Onboarding Protocol: {onboarding_protocol}")

                dev = Device(
                    device_name=device_name,
                    device_serial_number=serial_number,
                    onboarding_protocol=onboarding_protocol,
                    domain=domain
                )

                dev.save()
                print(f"Device '{device_name}' created successfully.\n")

        print("\nProcess completed. All domains and devices have been added.")
