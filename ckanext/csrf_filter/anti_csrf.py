# encoding: utf-8
""" Provides functions to help prevent Cross-Site Request Forgery,
based on the Double Submit Cookie pattern,
www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie

To apply the filter, use 'apply_token' to inject tokens into Flask responses,
and call 'check_csrf' on all requests.

Applying the filter to Pylons requires monkey-patching core functions.
"""

import hashlib
import hmac
from logging import getLogger
import random
import re
import time
import urllib
import six

from ckan import plugins
from ckan.common import config, request, g
import request_helpers

LOG = getLogger(__name__)

""" Used as the cookie name and input field name.
"""
TOKEN_FIELD_NAME = 'token'

"""
This will match a POST form that has whitespace after the opening tag (which all existing forms do).
Once we have injected a token immediately after the opening tag,
it won't match any more, which avoids redundant injection.
"""
POST_FORM = re.compile(
    r'(<form [^>]*method=["\']post["\'][^>]*>)(\s[^<]*<)',
    re.IGNORECASE | re.MULTILINE)

"""The format of the token HTML field.
"""
TOKEN_VALIDATION_PATTERN = re.compile(
    r'^[0-9a-z]+![0-9]+/[0-9]+/[-_a-z0-9%]+$',
    re.IGNORECASE)
API_URL = re.compile(r'^/api\b.*')
CONFIRM_MODULE_PATTERN = r'data-module=["\']confirm-action["\']'
CONFIRM_MODULE = re.compile(CONFIRM_MODULE_PATTERN)
HREF_URL_PATTERN = r'href=["\']([^"\']+)'

# We need to edit confirm-action links, which get intercepted by JavaScript,
# regardless of which order their 'data-module' and 'href' attributes appear.
CONFIRM_LINK = re.compile(r'(<a [^>]*{}[^>]*{})(["\'])'.format(
    CONFIRM_MODULE_PATTERN, HREF_URL_PATTERN),
    re.IGNORECASE | re.MULTILINE)
CONFIRM_LINK_REVERSED = re.compile(r'(<a [^>]*{})(["\'][^>]*{})'.format(
    HREF_URL_PATTERN, CONFIRM_MODULE_PATTERN),
    re.IGNORECASE | re.MULTILINE)

""" Tokens older than this will be rejected.
"""
TOKEN_EXPIRY_AGE = 60 * config.get('ckanext.csrf_filter.token_expiry_minutes', 30)

""" Tokens older than this will be replaced with new ones on the next response.
To minimise the risk of legitimate users presenting an expired token,
this should be significantly lower than the expiry age.
"""
TOKEN_RENEWAL_AGE = 60 * config.get('ckanext.csrf_filter.token_renewal_minutes', 10)


_site_url = six.moves.urllib.parse.urlparse(config.get('ckan.site_url', ''))
if _site_url.scheme == 'https':
    _secure_cookies = True
else:
    LOG.warn("Site %s is not secure! CSRF tokens may be exposed!", _site_url)
    _secure_cookies = False


# -------------
# Token parsing
# -------------


def _read_token_values(token):
    """ Parse the provided token string. Invalid tokens are parsed as empty dicts.
    """
    if not TOKEN_VALIDATION_PATTERN.match(token):
        return {}

    parts = token.split('!', 1)
    message = parts[1]
    # limiting to 2 means that even if a username contains a slash, it won't cause an extra split
    message_parts = message.split('/', 2)

    return {
        "message": message,
        "hash": parts[0],
        "timestamp": int(message_parts[0]),
        "nonce": int(message_parts[1]),
        "username": message_parts[2]
    }


def is_valid_token(token):
    """ Verify the integrity of the provided token.
    It must have the expected format (hash!timestamp/nonce/username),
    the hash must match the other values,
    the username must match the current account,
    and it must not be older than our limit (default 30 minutes).
    """
    token_values = _read_token_values(token)
    if 'hash' not in token_values:
        return False

    expected_hmac = six.ensure_text(_get_digest(token_values['message']))
    if not hmac.compare_digest(expected_hmac, six.ensure_text(token_values['hash'])):
        return False

    timestamp = token_values['timestamp']
    token_age = int(time.time()) - timestamp
    # allow tokens up to 'max_age' minutes old
    if token_age < 0 or token_age > TOKEN_EXPIRY_AGE:
        return False

    return token_values['username'] == _get_safe_username()


def is_soft_expired(token):
    """ Check whether the token is old enough to need rotation.
    It may still be valid, but it's time to generate a new one.

    The default rotation age is 10 minutes.
    """
    if not is_valid_token(token):
        return False

    token_values = _read_token_values(token)
    timestamp = token_values['timestamp']
    token_age = int(time.time()) - timestamp

    return token_age > TOKEN_RENEWAL_AGE


# --------------------
# Check request tokens
# --------------------


def _csrf_fail(message):
    """ Abort the request and return an error when there is a problem with the CSRF token.
    """
    LOG.error(message)
    plugins.toolkit.abort(403, "Your form submission could not be validated")


def _is_logged_in():
    """ Determine whether the user is currently logged in and thus needs a token.
    TODO Also require a token on login/logout forms.
    """
    return _get_user()


def is_request_exempt():
    """ Determine whether a request needs to provide a token.
    HTTP methods without side effects (GET, HEAD, OPTIONS) are exempt,
    as are API calls (which should instead provide an API key).
    """
    return not _is_logged_in() \
        or API_URL.match(request.path) \
        or request.method in {'GET', 'HEAD', 'OPTIONS'}


def get_cookie_token():
    """ Retrieve the token included in the request cookies, if it exists
    and is valid.
    """
    if TOKEN_FIELD_NAME in request.cookies:
        token = request.cookies.get(TOKEN_FIELD_NAME)
        if is_valid_token(token):
            LOG.debug("Obtaining token from cookie")
            return token

    return None


def get_submitted_form_token():
    """Retrieve the form token included in the request.

    This is normally a single 'token' parameter in the POST body.
    However, for compatibility with 'confirm-action' links,
    it is also acceptable to provide the token as a query string parameter.
    """
    if 'submitted_token' in request_helpers.scoped_attrs():
        return request_helpers.scoped_attrs()['submitted_token']

    post_tokens = request_helpers.get_post_params(TOKEN_FIELD_NAME)

    if post_tokens:
        if len(post_tokens) > 1:
            _csrf_fail("More than one CSRF token in form submission")
        else:
            token = post_tokens[0]
    else:
        get_tokens = request_helpers.get_query_params(TOKEN_FIELD_NAME)
        if len(get_tokens) == 1:
            # handle query string token if there are no POST parameters
            # this is needed for the 'confirm-action' JavaScript module
            token = get_tokens[0]
        else:
            _csrf_fail("Missing CSRF token in form submission")

    if not is_valid_token(token):
        _csrf_fail("Invalid CSRF token format")

    request_helpers.scoped_attrs()['submitted_token'] = token
    request_helpers.delete_param(TOKEN_FIELD_NAME)
    return token


def check_csrf():
    """ Check whether the request passes (or is exempt from) CSRF checks.
    """
    if not is_request_exempt():
        cookie_token = get_cookie_token()
        if cookie_token is None or cookie_token.strip() == "" \
                or cookie_token != get_submitted_form_token():
            _csrf_fail("Could not match cookie token with form token")


# ------------------------
# Populate response tokens
# ------------------------


def _get_user():
    """ Retrieve the current user object.
    """
    return g.userobj


def _get_safe_username():
    """ Retrieve the current username with unsafe characters URL-encoded.
    """
    return urllib.quote(_get_user().name, safe='')


def _get_secret_key():
    """ Retrieve the secret key to use in generating secure hashes.
    Currently this is the Beaker session secret.
    """
    return config.get('beaker.session.secret')


def _get_digest(message):
    """ Generate a secure (unforgeable) hash of the provided data.
    """
    return hmac.HMAC(_get_secret_key(), message, hashlib.sha512).hexdigest()


def _set_response_token_cookie(token, response):
    """ Add a generated token cookie to the HTTP response.
    """
    response.set_cookie(TOKEN_FIELD_NAME, token, secure=_secure_cookies, httponly=True)


def create_response_token():
    """ Generate an unforgeable CSRF token. The format of this token is:
    hash!timestamp/nonce/username
    where the hash is a secure HMAC of the other values plus a secret key.
    """
    username = _get_safe_username()
    timestamp = int(time.time())
    nonce = random.randint(1, 999999)
    message = "{}/{}/{}".format(timestamp, nonce, username)
    token = "{}!{}".format(_get_digest(message), message)

    return token


def get_response_token(response):
    """Retrieve the token to be injected into pages.

    This will be retrieved from the token cookie, if is valid and current.
    If not, a new token will be generated and a new cookie set.
    """
    # ensure that the same token is used when a page is assembled from pieces
    if 'response_token' in request_helpers.scoped_attrs():
        LOG.debug("Reusing response token from request attributes")
        token = request_helpers.scoped_attrs()['response_token']
    else:
        LOG.debug("Obtaining token from cookie")
        token = get_cookie_token()
        if not token or is_soft_expired(token):
            LOG.debug("No valid token found; making new token")
            token = create_response_token()
            _set_response_token_cookie(token, response)
        request_helpers.scoped_attrs()['response_token'] = token

    return token


def apply_token(html, response):
    """ Rewrite HTML to insert tokens if applicable.
    If a new token is generated, it will be added to 'response' as a cookie.
    """
    if not html or not _is_logged_in() or (
            not POST_FORM.search(html) and not CONFIRM_MODULE.search(html)):
        return html

    token = get_response_token(response)

    def insert_form_token(form_match):
        """ Inject a token into a POST form. """
        return form_match.group(1)\
            + '<input type="hidden" name="{}" value="{}"/>'.format(TOKEN_FIELD_NAME, token)\
            + form_match.group(2)

    def insert_link_token(link_match):
        """ Inject a token into a link that uses data-module="confirm-action".
        These links are picked up by JavaScript and converted into empty POST requests.
        """
        if TOKEN_FIELD_NAME + '=' in link_match.group(1):
            return link_match.group(0)
        if '?' in link_match.group(2):
            separator = '&'
        else:
            separator = '?'
        return link_match.group(1) + separator + TOKEN_FIELD_NAME + '=' + token + link_match.group(3)

    html = POST_FORM.sub(insert_form_token, html)
    html = CONFIRM_LINK.sub(insert_link_token, html)
    html = CONFIRM_LINK_REVERSED.sub(insert_link_token, html)
    if getattr(response, 'data', None):
        response.data = html
    return html