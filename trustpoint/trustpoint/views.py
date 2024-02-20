"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404).
"""


from django.views.generic.base import RedirectView


class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent = True
    pattern_name = 'home:dashboard'
