from behave import when, then, given
from behave.api.pending_step import StepNotImplementedError


@given('the system supports the following languages:')
def step_given_supported_languages(context):
    """
    Ensures that the system supports multiple languages.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError("STEP: Given the system supports the following languages")


@given('a new user accesses the system with browser language {language}')
def step_given_new_user_with_browser_language(context, language):
    """
    Simulates a new user accessing the system with a specified browser language.

    Args:
        language (str): The language detected from the user's browser settings.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f"STEP: Given a new user accesses the system with browser language {language}")


@then(u'the system should display the UI in {language}')
def step_then_ui_displays_language(context, language):
    """
    Ensures that the UI is displayed in the correct language.

    Args:
        language (str): Expected language for the UI.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f"STEP: Then the system should display the UI in {language}")


@given(u'a logged-in user')
def step_given_logged_in_user(context):
    """
    Simulates a logged-in user.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError("STEP: Given a logged-in user")


@when('the user selects {language} from the language settings')
def step_when_user_selects_language(context, language):
    """
    Simulates a user selecting a different language.

    Args:
        language (str): Language chosen by the user.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f"STEP: When the user selects {language} from the language settings")


@given('a user has selected {language} as their preferred language')
def step_given_user_preferred_language(context, language):
    """
    Simulates a user with a saved language preference.

    Args:
        language (str): The preferred language set by the user.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError(f"STEP: Given a user has selected {language} as their preferred language")


@when('the user logs out and logs back in')
def step_when_user_relogs(context):
    """
    Simulates a user logging out and logging back in.

    Raises:
        StepNotImplementedError: Step not yet implemented.
    """
    raise StepNotImplementedError("STEP: When the user logs out and logs back in")
