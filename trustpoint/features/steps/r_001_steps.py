import string
from typing import NoReturn

from behave import given, then, when
from behave.api.pending_step import StepNotImplementedError


@given('the identity {name} with {identifier} exists')
def step_identity_exists(context: object, name: string, identifier: string) -> NoReturn:
    """Ensures that an identity with the specified name and identifier exists in the system.

    :param context: the context object
    :param name: the name of the identity
    :param identifier: the ID of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return

    """
    msg = 'Step not implemented: Identity creation or precondition setup.'
    raise StepNotImplementedError(msg)


@when('the admin navigates to the identity details page for {name}')
def step_impl(context: object, name: string) -> NoReturn:
    """The admin user should navigate to the details page using the UI.

    :param context: the context object
    :param name: the name of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = f'STEP: When the admin navigates to the identity details page for {name}'
    raise StepNotImplementedError(msg)


@then('the system should display the correct details for {name} and {identifier}')
def step_impl(context: object, name: string, identifier: string) -> NoReturn:
    """The system should post the changes visible to the admin.

    :param context: the context object
    :param name: the name of the identity
    :param identifier: the ID of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = f'STEP: Then the system should display the correct details for {name} and {identifier}'
    raise StepNotImplementedError(msg)


@when('the admin navigates to the "Create Identity" page')
def step_navigate_create_identity(context: object) -> NoReturn:
    """Navigates to the "Create Identity" page within the TPC_Web interface.

    This step simulates the admin user accessing the page to add a new identity.

    :param context: the context object

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = 'Step not implemented: Navigate to Create Identity page.'
    raise StepNotImplementedError(msg)


@when('the admin fills in the identity details with {name} and {identifier}')
def step_fill_identity_details(context: object, name: string, identifier: string) -> NoReturn:
    """Fills in the form fields for creating a new identity.

    :param context: the context object
    :param name: the name of the identity
    :param identifier: the ID of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = 'Step not implemented: Fill identity details.'
    raise StepNotImplementedError(msg)


@when('the admin submits the form')
def step_submit_form(context: object) -> NoReturn:
    """Submits the "Create Identity" form.

    This step triggers the creation process for the new identity.

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = 'Step not implemented: Submit the Create Identity form.'
    raise StepNotImplementedError(msg)


@then('the new identity {name} with {identifier} should appear in the identity list')
def step_identity_in_list(context: object, name: string, identifier: string) -> NoReturn:
    """Verifies that the newly created identity appears in the identity list.

    :param context: the context object
    :param name: the name of the identity
    :param identifier: the ID of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = 'Step not implemented: Check for identity in the list.'
    raise StepNotImplementedError(msg)


@when('the admin updates the name to {name} and identifier to {identifier}')
def step_impl(context: object, name: string, identifier: string) -> NoReturn:
    """The admin should put in a new name and/or a new identifier.

    :param context: the context object
    :param name: the name of the identity
    :param identifier: the ID of the identity

    :raises StepNotImplementedError: This step is not yet implemented.

    :return: No Return
    """
    msg = f'STEP: When the admin updates the name to {name} and identifier to {identifier}'
    raise StepNotImplementedError(msg)


@when('the admin saves the changes')
def step_impl(context) -> NoReturn:
    msg = 'STEP: When the admin saves the changes'
    raise StepNotImplementedError(msg)


@then('the updated identity {name} with {identifier} should appear in the identity list')
def step_impl(context, name, identifier) -> NoReturn:
    msg = f'STEP: Then the updated identity {name} with {identifier} should appear in the identity list'
    raise StepNotImplementedError(msg)


@when('the admin deletes the identity with the name {name}')
def step_impl(context, name) -> NoReturn:
    msg = f'STEP: When the admin deletes the identity with the name {name}'
    raise StepNotImplementedError(msg)


@then('the identity {name} should no longer appear in the identity list')
def step_impl(context, name) -> NoReturn:
    msg = f'STEP: Then the identity {name} should no longer appear in the identity list'
    raise StepNotImplementedError(msg)


@when('the admin attempts to view the details of a non-existent identity {non_existent_ID}')
def step_impl(context, non_existent_ID) -> NoReturn:
    msg = f'STEP: When the admin attempts to view the details of a non-existent identity {non_existent_ID}'
    raise StepNotImplementedError(msg)
