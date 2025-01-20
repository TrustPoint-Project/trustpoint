from behave import given, when
from behave.api.pending_step import StepNotImplementedError

# Background steps
@given("the admin is registered and logged into the system")
def step_admin_logged_in(context):
    raise StepNotImplementedError("The step to log in the admin is not yet implemented.")

@given("the TPC_Web and TPC_CLI services are running")
def step_services_running(context):
    raise StepNotImplementedError("The step to check TPC_Web and TPC_CLI services is not yet implemented.")

@when('the admin opens {component}')
def step_open_component(context, component):
    raise StepNotImplementedError(f"The step to open {component} is not yet implemented.")

@when("the admin navigates to the list of identities")
def step_navigate_to_identities(context):
    raise StepNotImplementedError("The step to navigate to the list of identities is not yet implemented.")
