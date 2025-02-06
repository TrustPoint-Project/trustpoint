from behave import given, then, when
from behave.api.pending_step import StepNotImplementedError


@given('the system enforces certificate validation for all devices')
def step_given_system_enforces_cert_validation(context):
    """Ensures that the system requires all devices to present valid certificates for communication.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: Given the system enforces certificate validation for all devices')


@given('a device has a {validity} certificate')
def step_given_device_with_cert(context, validity):
    """Simulates a device possessing a certificate.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Given a device has a {validity} certificate')


@given('a device does not present a certificate')
def step_given_device_without_cert(context):
    """Simulates a device attempting to communicate without providing a certificate.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: Given a device does not present a certificate')


@when('the device attempts to establish communication')
def step_when_device_attempts_communication(context):
    """Simulates a device attempting to establish communication with the system.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When the device attempts to establish communication')


@then('the system should {allow_deny} the communication')
def step_then_allow_deny_communication(context, allow_deny):
    """Ensures that the system allows/denies communication when a valid certificate is presented.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Then the system should {allow_deny} the communication')


@then('log the authentication failure with reason {reason}')
def step_then_log_failure(context, reason):
    """Ensures that the system logs authentication failures with the appropriate reason.

    Args:
        reason (str): The reason for authentication failure.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Then log the authentication failure with reason {reason}')
