"""Adds Issuing CAs, Domains and Devices with different onboarding protocols."""

import random
import string
from django.core.management.base import BaseCommand

from pki.models import DomainModel, IssuingCaModel
from devices.models import DeviceModel
from django.core.management import call_command


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


        onboarding_protocols = [
            DeviceModel.OnboardingProtocol.NO_ONBOARDING.value,
            DeviceModel.OnboardingProtocol.CMP_IDEVID.value,
            DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET.value,
        ]

        print("Starting the process of adding domains and devices...\n")

        for domain_name, devices in data.items():
            issuing_ca = random.choice(
                [
                    'issuing-ca-a',
                    'issuing-ca-b',
                    'issuing-ca-c',
                    'issuing-ca-d',
                    'issuing-ca-e',
                    'issuing-ca-f',
                 ])
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

                onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING \
                    if onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING \
                    else DeviceModel.OnboardingStatus.PENDING

                domain_credential_onboarding = False \
                    if onboarding_protocol == DeviceModel.OnboardingProtocol.NO_ONBOARDING \
                    else True

                pki_protocol = DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE.value \
                    if (onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_IDEVID or
                        onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET) \
                    else random.choice([DeviceModel.PkiProtocol.MANUAL.value,
                                        DeviceModel.PkiProtocol.CMP_SHARED_SECRET.value])

                dev = DeviceModel(
                    unique_name=device_name,
                    serial_number=serial_number,
                    domain=domain,
                    onboarding_protocol=onboarding_protocol,
                    onboarding_status=onboarding_status,
                    domain_credential_onboarding=domain_credential_onboarding,
                    pki_protocol=pki_protocol
                )

                try:
                    dev.save()
                    if dev.pk:
                        print(f"Creating device '{dev.unique_name}' (ID {dev.pk}) in domain '{dev.domain}' with:")
                        print(f"  - Serial Number: {dev.serial_number}")
                        print(f"  - Onboarding Protocol: {dev.onboarding_protocol}")
                    else:
                        print(f"Device '{device_name}' was not saved correctly.")
                except Exception as e:
                    print(f"Failed to create device '{device_name}': {e}")

        print("\nProcess completed. All domains and devices have been added.")
