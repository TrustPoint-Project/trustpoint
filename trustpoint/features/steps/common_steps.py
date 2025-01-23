from behave import given, when, then
from behave.api.pending_step import StepNotImplementedError

# Background steps
@given('the server is running and reachable')
def step_server_running(context):
    raise StepNotImplementedError('The step to check if the server is running and reachable is not yet implemented.')

@given('the admin is registered and logged into the system')
def step_admin_logged_in(context):
    raise StepNotImplementedError('The step to log in the admin is not yet implemented.')

@given('the TPC_Web and TPC_CLI services are running')
def step_services_running(context):
    raise StepNotImplementedError('The step to check TPC_Web and TPC_CLI services is not yet implemented.')

@when('the admin opens {component}')
def step_open_component(context, component):
    raise StepNotImplementedError(f"The step to open {component} is not yet implemented.")

@when('the admin navigates to the list of identities')
def step_navigate_to_identities(context):
    raise StepNotImplementedError('The step to navigate to the list of identities is not yet implemented.')

@then('the server should return a status code of {status_code}')
def step_check_status_code(context, status_code):
    raise StepNotImplementedError(f"Verify the server returns the expected status code: {status_code}.")

@then('the response should indicate {error_reason}')
def step_response_error_reason(context, error_reason):
    raise StepNotImplementedError(f"Check that the response indicates the error: {error_reason}.")

@then('the certificate status should change to {revocation_status}')
def step_certificate_status_change(context, revocation_status):
    raise StepNotImplementedError(f"Ensure the certificate status changes to: {revocation_status}.")

