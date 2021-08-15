# encoding: utf-8
""" Provides functions to help prevent Cross-Site Request Forgery,
based on the Double Submit Cookie pattern,
www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie

To apply the filter, use 'apply_token' to inject tokens into Flask responses,
and call 'check_csrf' on all requests to determine whether they are valid.

Applying the filter to Pylons requires monkey-patching core functions.
"""

import hashlib
import hmac
from logging import getLogger
import random
import re
import time
import six
from six.moves.urllib.parse import quote, urlparse

from ckanext.csrf_filter.request_helpers import RequestHelper

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
    r'^[0-9a-z]+![0-9]+/[0-9]+/[-_a-z0-9%+=]+$',
    re.IGNORECASE)
API_URL = re.compile(r'^/api\b.*')
LOGIN_URL = re.compile(r'^(/user)?/log(ged_)?in(_generic)?')
CONFIRM_MODULE_PATTERN = r'data-module=["\']confirm-action["\']'
CONFIRM_MODULE = re.compile(CONFIRM_MODULE_PATTERN)
HREF_URL_PATTERN = r'href=["\']([^"\']+)'
ANONYMOUS_USERNAME = '__anonymous__'

# We need to edit confirm-action links, which get intercepted by JavaScript,
# regardless of which order their 'data-module' and 'href' attributes appear.
CONFIRM_LINK = re.compile(r'(<a [^>]*{}[^>]*{})(["\'])'.format(
    CONFIRM_MODULE_PATTERN, HREF_URL_PATTERN),
    re.IGNORECASE | re.MULTILINE)
CONFIRM_LINK_REVERSED = re.compile(r'(<a [^>]*{})(["\'][^>]*{})'.format(
    HREF_URL_PATTERN, CONFIRM_MODULE_PATTERN),
    re.IGNORECASE | re.MULTILINE)


def configure(config):
    """ Configure global values for the filter.
    """
    global secure_cookies
    global secret_key
    global token_expiry_age
    global token_renewal_age

    site_url = urlparse(config.get('ckan.site_url', ''))
    if site_url.scheme == 'https':
        secure_cookies = True
    else:
        LOG.warning("Site %s is not secure! CSRF tokens may be exposed!", site_url)
        secure_cookies = False

    key_fields = ['ckanext.csrf_filter.secret_key',
                  'beaker.session.secret',
                  'flask.secret_key']
    secret_key = None
    for field in key_fields:
        secret_key = config.get(field)
        if secret_key:
            LOG.info("Obtained secret key from %s", field)
            break
    else:
        raise ValueError("No secret key provided for CSRF tokens; populate one of %s",
                         key_fields)
    token_expiry_age = 60 * config.get('ckanext.csrf_filter.token_expiry_minutes', 30)
    token_renewal_age = 60 * config.get('ckanext.csrf_filter.token_renewal_minutes', 10)


# -------------
# Token parsing
# -------------


def _read_token_values(token):
    """ Parse the provided token string. Invalid tokens are parsed as empty dicts.
    """
    if not token or not TOKEN_VALIDATION_PATTERN.match(token):
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
    if token_age < 0 or token_age > token_expiry_age:
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

    return token_age > token_renewal_age


# --------------------
# Check request tokens
# --------------------


def _is_login_url(request):
    """ Determine whether the user is visiting a login-related URL
    that should be protected with a token.
    """
    request_helper = RequestHelper(request)
    path = request_helper.get_path()
    if LOGIN_URL.match(path):
        return True
    try:
        return path.startswith(getattr(
            request_helper.get_environ()[u'repoze.who.plugins'][u'friendlyform'],
            u'login_handler_path', None))
    except (KeyError, AttributeError):
        # not necessarily an error, we might just not use FriendlyForm
        return False


def is_logged_in(request=None):
    """ Determine whether the user is logged in, or about to log in,
    and thus needs a token.
    """
    return _get_user() or _is_login_url(request)


def _is_request_exempt(request):
    """ Determine whether a request needs to provide a token.
    HTTP methods without side effects (GET, HEAD, OPTIONS) are exempt,
    as are API calls (which should instead provide an API key).
    """
    request_helper = RequestHelper(request)
    return not is_logged_in(request) \
        or API_URL.match(request_helper.get_path()) \
        or request_helper.get_method() in {'GET', 'HEAD', 'OPTIONS'}


def _get_cookie_token(request):
    """ Retrieve the token included in the request cookies, if it exists
    and is valid.
    """
    token = RequestHelper(request).get_cookie(TOKEN_FIELD_NAME)
    if is_valid_token(token):
        return token

    return None


def _get_submitted_form_token(request):
    """Retrieve the form token included in the request.

    This is normally a single 'token' parameter in the POST body.
    However, for compatibility with 'confirm-action' links,
    it is also acceptable to provide the token as a query string parameter.
    """
    request_helper = RequestHelper(request)
    if TOKEN_FIELD_NAME in request_helper.scoped_attrs():
        return request_helper.scoped_attrs()[TOKEN_FIELD_NAME]

    post_tokens = request_helper.get_post_params(TOKEN_FIELD_NAME)

    if post_tokens:
        if len(post_tokens) > 1:
            LOG.error("More than one CSRF token in form submission")
            return None
        else:
            token = post_tokens[0]
    else:
        get_tokens = request_helper.get_query_params(TOKEN_FIELD_NAME)
        if len(get_tokens) == 1:
            # handle query string token if there are no POST parameters
            # this is needed for the 'confirm-action' JavaScript module
            token = get_tokens[0]
        else:
            LOG.error("Missing CSRF token in form submission")
            return None

    if not is_valid_token(token):
        LOG.error("Invalid CSRF token format")
        return None

    request_helper.scoped_attrs()[TOKEN_FIELD_NAME] = token
    request_helper.delete_param(TOKEN_FIELD_NAME)
    return token


def check_csrf(request=None):
    """ Check whether the request passes (or is exempt from) CSRF checks.
    Returns True if valid or exempt, False if invalid.
    """
    if _is_request_exempt(request):
        return True
    cookie_token = _get_cookie_token(request)
    if cookie_token and cookie_token.strip() != ""\
            and cookie_token == _get_submitted_form_token(request):
        return True
    else:
        LOG.error("Could not match cookie token with form token")
        return False


# ------------------------
# Populate response tokens
# ------------------------


def _get_user():
    """ Retrieve the current user object.
    """
    from ckan.common import g
    if 'userobj' in dir(g):
        return g.userobj
    else:
        return None


def _get_safe_username():
    """ Retrieve a with unsafe characters URL-encoded.
    """
    userobj = _get_user()
    if userobj and userobj.name:
        if userobj.name == ANONYMOUS_USERNAME:
            raise ValueError("User account is named %s!",
                             ANONYMOUS_USERNAME)
        return quote(userobj.name, safe='')
    else:
        return ANONYMOUS_USERNAME


def _get_digest(message):
    """ Generate a secure (unforgeable) hash of the provided data.
    """
    return hmac.HMAC(six.ensure_binary(secret_key), six.ensure_binary(message), hashlib.sha512).hexdigest()


def _set_response_token_cookie(token, response):
    """ Add a generated token cookie to the HTTP response.
    """
    response.set_cookie(TOKEN_FIELD_NAME, token, secure=secure_cookies, httponly=True)


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


def get_response_token(response, request=None):
    """Retrieve the token to be injected into pages.

    This will be retrieved from the token cookie, if is valid and current.
    If not, a new token will be generated and a new cookie set.
    """
    # ensure that the same token is used when a page is assembled from pieces
    request_helper = RequestHelper(request)
    if 'response_token' in request_helper.scoped_attrs():
        token = request_helper.scoped_attrs()['response_token']
    else:
        token = _get_cookie_token(request)
        if not token or is_soft_expired(token):
            LOG.debug("No valid token found; making new token")
            token = create_response_token()
            _set_response_token_cookie(token, response)
        request_helper.scoped_attrs()['response_token'] = token

    return token


def insert_token(html, token, request=None):
    """ Rewrite HTML to insert tokens if applicable.
    """
    if not html or not is_logged_in(request) or (
            not POST_FORM.search(html) and not CONFIRM_MODULE.search(html)):
        return html

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
    return html


def apply_token(response, request=None):
    """ Rewrite HTML to insert tokens if applicable.
    If a new token is generated, it will be added to 'response' as a cookie.
    """
    html = getattr(response, 'data', None)
    if not html or not is_logged_in(request):
        return response

    token = get_response_token(response)
    html = insert_token(html, token)
    if hasattr(response, 'data'):
        response.data = html
    return response
