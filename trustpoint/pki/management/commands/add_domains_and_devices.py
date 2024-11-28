# add_domains_and_devices.py
import random
import string
from pathlib import Path
from django.core.management.base import BaseCommand

from pki.models import DomainModel, IssuingCaModel
from devices.models import Device
from django.core.management import call_command
from pki.initializer import UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer


class Command(BaseCommand):
    help = 'Add domains and associated device names with random onboarding protocol and serial number'

    def handle(self, *args, **kwargs):
        call_command('create_multiple_test_issuing_cas')

        data = {
            "arburg": [
                "ALLROUNDER-Injection-Molding-Machine",
                "freeformer-3D-Printer",
                "SELOGICA-Control-System",
                "MULTILIFT-Robotic-Systems",
                "ARBIDRIVE-Servo-Motor",
                "ALS_Arburg-Leitrechner-System"
            ],
            "homag": [
                "CENTATEQ-CNC-Processing-Center",
                "EDGETEQ-Edge-Banding-Machine",
                "powerTouch-Control",
                "intelliGuide-Assist-System",
                "DRILLTEQ-Drilling-and-Dowel-Insertion-Machine",
                "STORETEQ-Storage-System"
            ],
            "belden": [
                "Hirschmann-Industrial-Ethernet-Switches",
                "Lumberg-Automation-Connectors",
                "GarrettCom-Magnum-Routers",
                "TROMPETER-Coaxial-Connectors",
                "Belden-I_O-Modules"
            ],
            "siemens": [
                "SIMATIC-PLC",
                "SINAMICS-Drive-Systems",
                "SIRIUS-Control-Devices",
                "SIMOTICS-Electric-Motors",
                "SIMATIC-HMI-Panels",
                "SITOP-Power-Supplies"
            ],
            "phoenix_contact": [
                "CLIPLINE-Terminal-Blocks",
                "QUINT-Power-Supplies",
                "PLCnext-Control",
                "TERMITRAB-Surge-Protection",
                "CONTACTRON-Motor-Starters",
                "ME-PLC_Modular-Controller"
            ],
            "schmalz": [
                "Vacuum-Generators",
                "Vacuum-Grippers",
                "Vacuum-Clamping-Systems",
                "Suction-Pads",
                "Vacuum-Layer-Grippers",
                "Vacuum-Ejectors"
            ]
        }

        # onboarding_protocols = [protocol.value for protocol in Device.OnboardingProtocol]
        onboarding_protocols = [Device.OnboardingProtocol.TP_CLIENT.value, Device.OnboardingProtocol.MANUAL.value]

        print("Starting the process of adding domains and devices...\n")

        for domain_name, devices in data.items():
            issuing_ca = random.choice(['issuing-ca-a', 'issuing-ca-b', 'issuing-ca-c'])
            domain, created = DomainModel.objects.get_or_create(unique_name=domain_name)
            domain.issuing_ca = IssuingCaModel.objects.get(unique_name=issuing_ca)
            domain.save()

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
