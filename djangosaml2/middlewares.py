import logging

from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from djangosaml2.views import login as saml_login

logger = logging.getLogger(__name__)


class HintCookieMiddleware(MiddlewareMixin):

    def process_request(self, request):
        try:
            hint_cookie_name = settings.SAML_HINT_COOKIE_NAME
            if not hint_cookie_name:
                raise AttributeError
        except AttributeError:
            raise ImproperlyConfigured(
                "SAML_HINT_COOKIE_NAME not defined on use of HintCookieMiddleware")

        # To avoid a loop
        # saml2_login eventually redirects to saml2_acs
        if request.path == reverse('saml2_login') or request.path == reverse('saml2_acs'):
            return None

        saml_hint_cookie = request.COOKIES.get(hint_cookie_name)

        # If logged out and the hint cookie is available
        # automatically do an SP initiated login
        if not request.user.is_authenticated and saml_hint_cookie:
            logger.info('SAML: Hint cookie present. Initiating an auto login.')
            return saml_login(request)

        # If logged in and the hint cookie is missing
        # automatically do a logout
        if request.user.is_authenticated and not saml_hint_cookie:
            logger.info('SAML: Hint cookie missing. Initiating an auto logout.')
            logout(request)
