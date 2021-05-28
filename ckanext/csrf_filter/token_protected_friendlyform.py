# encoding: utf-8
""" Extends the 'friendlyform' Repoze.who plugin to check for a CSRF token.
"""

from logging import getLogger
from repoze.who.plugins import friendlyform
from webob import Request

import anti_csrf

LOG = getLogger(__name__)


class TokenProtectedFriendlyFormPlugin(friendlyform.FriendlyFormPlugin):
    """ Extends the FriendlyFormPlugin to validate CSRF tokens before logging in.

    Not currently compatible with other FriendlyForm subclasses.
    """

    def identify(self, environ):
        """ Check for a valid CSRF token before allowing login.
        """
        path_info = environ['PATH_INFO']

        if path_info == self.login_handler_path:
            request = Request(environ, charset=self.charset)
            LOG.debug("Checking for CSRF token on path %s", path_info)
            if not anti_csrf.check_csrf(request):
                LOG.warning("Unable to validate CSRF token on login")
                return None
        return super(TokenProtectedFriendlyFormPlugin, self).identify(environ)
