from behave import given, then, when
from behave.api.pending_step import StepNotImplementedError


@given('the user has role {role}')
def step_given_user_role(context, role):
    """Ensures the user has a specified role.

    Args:
        role (str): The role assigned to the user.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Given the user has role {role}')


@given('a certificate template named {template_name} exists')
def step_given_certificate_template_exists(context, template_name):
    """Ensures that a specific certificate template exists.

    Args:
        template_name (str): The name of the certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Given a certificate template named {template_name} exists')


@when('the user attempts to access certificate templates')
def step_when_user_attempts_access_templates(context):
    """Simulates a user attempting to access certificate templates.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When the user attempts to access certificate templates')


@when('the user attempts to modify the certificate template')
def step_when_user_attempts_modify_template(context):
    """Simulates a user attempting to modify a certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When the user attempts to modify the certificate template')


@when('an unauthorized user attempts to access it')
def step_when_unauthorized_access_attempted(context):
    """Simulates an unauthorized user attempting to access a sensitive certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When an unauthorized user attempts to access it')


@when('a non-admin user attempts to delete it')
def step_when_non_admin_attempts_delete(context):
    """Simulates a non-admin user attempting to delete a certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When a non-admin user attempts to delete it')


@when('an admin exports the template')
def step_when_admin_exports_template(context):
    """Simulates an admin exporting a certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When an admin exports the template')


@when('a non-admin user attempts to export the template')
def step_when_non_admin_attempts_export(context):
    """Simulates a non-admin user attempting to export a certificate template.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: When a non-admin user attempts to export the template')


@then('access should be {access_outcome}')
def step_then_access_outcome(context, access_outcome):
    """Ensures that access to certificate templates is correctly granted or denied.

    Args:
        access_outcome (str): The expected access outcome ("granted" or "denied").

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Then access should be {access_outcome}')


@then('modification should be {modification_outcome}')
def step_then_modification_outcome(context, modification_outcome):
    """Ensures that modification attempts are correctly handled.

    Args:
        modification_outcome (str): The expected modification outcome ("allowed" or "denied").

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Then modification should be {modification_outcome}')


@then('the deletion should be rejected')
def step_then_deletion_rejected(context):
    """Ensures that unauthorized deletion attempts are rejected.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: Then the deletion should be rejected')


@then('an error message {error_message} should be shown')
def step_then_error_message_shown(context, error_message):
    """Ensures that an appropriate error message is shown for unauthorized actions.

    Args:
        error_message (str): The expected error message.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f'STEP: Then an error message {error_message} should be shown')


@then('the exported template should be encrypted')
def step_then_export_encrypted(context):
    """Ensures that exported certificate templates are encrypted.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: Then the exported template should be encrypted')


@then('export should be denied')
def step_then_export_denied(context):
    """Ensures that unauthorized export attempts are denied.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError('STEP: Then export should be denied')


@then('the attempt should be logged')
def step_impl(context):
    raise StepNotImplementedError('STEP: Then the attempt should be logged')
