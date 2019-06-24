import logging

from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

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

        saml_hint_cookie = request.COOKIES.get(hint_cookie_name)
        if saml_hint_cookie:
            # Automatically do an SP initiated login
            logger.info('SAML: Hint cookie present. Initiating an auto login.')
            return HttpResponseRedirect(reverse('djangosaml2:login'))
        else:
            # Assuming the user would have logged out in the IdP
            # Logout the user
            logger.info('SAML: Hint cookie missing. Initiating an auto logout.')
            logout(request)
