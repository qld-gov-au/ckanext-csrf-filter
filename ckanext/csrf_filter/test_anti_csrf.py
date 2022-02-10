# encoding: utf-8

'''Tests that the CSRF filter validates tokens correctly.
'''

import re
import unittest

from ckanext.csrf_filter import anti_csrf
import six

NUMBER_FIELDS = re.compile(r'(![0-9]+)/([0-9]+)/')
STUB_TOKEN = 'some_token_or_other'


html_cases = [
    {"input": '''<form method="POST">
             Form contents here</form>''',
     "expected": '''<form method="POST"><input type="hidden" name="{}" value="{}"/>
             Form contents here</form>'''
     },
    {"input": '''<a data-module="confirm-action" href="/some/path">
             Click here</a>''',
     "expected": '''<a data-module="confirm-action" href="/some/path?{}={}">
             Click here</a>'''
     },
    {"input": '''<a data-module="confirm-action" href="/some/path?foo=baz">
             Click here</a>''',
     "expected": '''<a data-module="confirm-action" href="/some/path?foo=baz&{}={}">
             Click here</a>'''
     },
    {"input": '''<a href="/some/path" data-module="confirm-action">
             Click here</a>''',
     "expected": '''<a href="/some/path?{}={}" data-module="confirm-action">
             Click here</a>'''
     },
]


class MockUser(object):
    """ Stub class to represent a logged-in user.
    """

    def __init__(self, name):
        """ Set up a stub name to return.
        """
        self.name = name


class MockRequest(object):
    """ Stub class to represent a HTTP request.
    """

    def __init__(self, method, path, cookies):
        """ Set up a stub name to return.
        """
        self.environ = {'webob.adhoc_attrs': {}}
        self.cookies = cookies
        self.method = method
        self.path = path


def mock_objects(username=None):
    """ Monkey-patch necessary functions in the CSRF filter to imitate core CKAN.
    """
    anti_csrf.configure({
        'ckanext.csrf_filter.secret_key': 'secret',
        'ckan.site_url': 'https://unit-test'})
    if username:
        anti_csrf._get_user = lambda: MockUser(username)
    else:
        anti_csrf._get_user = lambda: None


class TestAntiCsrfFilter(unittest.TestCase):
    """ Test our anti-CSRF filter with mock CKAN objects.
    """

    def test_read_token_values(self):
        """ Test that tokens are parsed correctly. Note that invalid tokens are parsed as blanks.
        """
        good_token = 'hash!123/456/someuser'
        expected_value = {
            "hash": six.ensure_text("hash"),
            "message": "123/456/someuser",
            "timestamp": 123,
            "nonce": 456,
            "username": "someuser"
        }
        bad_tokens = [
            None,
            '',
            'aaa',
            good_token.replace('/', '!'),
            NUMBER_FIELDS.sub(r'\1a/\2/', good_token),
            NUMBER_FIELDS.sub(r'\1/\2a/', good_token)
        ]

        print("Testing good token '{}'".format(good_token))
        self.assertEqual(anti_csrf._read_token_values(good_token), expected_value)
        for bad_token in bad_tokens:
            print("Testing bad token '{}'".format(bad_token))
            self.assertEqual(anti_csrf._read_token_values(bad_token), {})

    def test_is_valid_token(self):
        """ Test that tokens are properly validated.
        Correct format, current timestamp, HMAC integrity check passed.
        """
        mock_objects()

        good_token = anti_csrf.create_response_token()
        bad_tokens = [
            good_token + '-evil',
            good_token.replace('!', 'x!'),
            NUMBER_FIELDS.sub(r'!123/\2/', good_token),
            NUMBER_FIELDS.sub(r'\1/123/', good_token)
        ]

        print("Testing good token {}".format(good_token))
        self.assertTrue(anti_csrf.is_valid_token(good_token))
        for bad_token in bad_tokens:
            print("Testing invalid token '{}'".format(bad_token))
            self.assertFalse(anti_csrf.is_valid_token(bad_token))
            self.assertFalse(anti_csrf.is_soft_expired(bad_token))

    def test_soft_token_expiry(self):
        """ Test that tokens are rotated when they are getting old.
        They may still be accepted after this point.
        """
        mock_objects('unit-test')
        good_token = anti_csrf.create_response_token()
        self.assertFalse(anti_csrf.is_soft_expired(good_token))

        import time
        print("Generating old token at {}".format(time.time()))
        old_values = "{}/{}/{}".format(int(time.time()) - 11 * 60, 123, 'unit-test')
        old_token = "{}!{}".format(anti_csrf._get_digest(old_values), old_values)

        print("Testing soft-expired token {}".format(old_token))
        self.assertTrue(anti_csrf.is_soft_expired(old_token))

    def test_username_with_slash(self):
        """ Test that usernames containing slashes are handled robustly.
        """
        mock_objects('abc_123')
        bad_token = anti_csrf.create_response_token()
        mock_objects('abc/123')
        good_token = anti_csrf.create_response_token()

        print("Testing valid username token '{}'".format(good_token))
        self.assertTrue(anti_csrf.is_valid_token(good_token))
        print("Testing wrong user token '{}'".format(bad_token))
        self.assertFalse(anti_csrf.is_valid_token(bad_token))

    def test_inject_token(self):
        """ Test that tokens are correctly injected into HTML when logged in.
        """
        mock_objects('unit-test')
        for case in html_cases:
            injected_html = anti_csrf.insert_token(case['input'], STUB_TOKEN)
            print("Expecting exactly one token in {}".format(injected_html))
            self.assertEqual(injected_html,
                             case['expected'].format(anti_csrf.TOKEN_FIELD_NAME, STUB_TOKEN))
            self.assertEqual(injected_html, anti_csrf.insert_token(injected_html, STUB_TOKEN))

    def test_inject_token_on_login_form(self):
        """ Test that tokens are correctly injected into login form.
        """
        mock_objects()
        request = MockRequest(method='', path='/user/login', cookies={'auth_tkt': 'unit-test'})
        for case in html_cases:
            injected_html = anti_csrf.insert_token(case['input'], STUB_TOKEN, request=request)
            print("Expecting exactly one token in {}".format(injected_html))
            self.assertEqual(injected_html,
                             case['expected'].format(anti_csrf.TOKEN_FIELD_NAME, STUB_TOKEN))
            self.assertEqual(injected_html, anti_csrf.insert_token(injected_html, STUB_TOKEN, request=request))

    def test_not_inject_token_when_logged_out(self):
        """ Test that tokens are not injected when not logged in.
        """
        mock_objects()
        request = MockRequest(method='', path='/foo', cookies={'auth_tkt': 'unit-test'})
        for case in html_cases:
            injected_html = anti_csrf.insert_token(case['input'], STUB_TOKEN, request=request)
            print("Expecting no token in {}".format(injected_html))
            self.assertEqual(injected_html, case['input'])

    def test_required_config(self):
        """ Tests that the filter is configured correctly from inputs
        """
        config = {}
        self.assertRaises(ValueError, anti_csrf.configure, config)

        # secret HMAC key
        config['flask.secret_key'] = 'flask_key'
        anti_csrf.configure(config)
        self._check_config('flask_key')

        config['beaker.session.secret'] = 'beaker_key'
        anti_csrf.configure(config)
        self._check_config('beaker_key')

        config['ckanext.csrf_filter.secret_key'] = 'secret_key'
        anti_csrf.configure(config)
        self._check_config('secret_key')

        # cookie 'Secure' flag
        config['ckan.site_url'] = 'https://unit-test'
        anti_csrf.configure(config)
        self._check_config('secret_key', secure_cookies=True)

        # cookie ages
        config['ckanext.csrf_filter.token_expiry_minutes'] = 60
        config['ckanext.csrf_filter.token_renewal_minutes'] = 30
        anti_csrf.configure(config)
        self._check_config('secret_key', secure_cookies=True,
                           token_expiry_age=3600, token_renewal_age=1800)

    def _check_config(self, secret_key, secure_cookies=False,
                      token_expiry_age=1800, token_renewal_age=600):
        """ Check that the config values of the CSRF filter are as expected.
        """
        self.assertEqual(anti_csrf.secret_key, secret_key)
        self.assertEqual(anti_csrf.secure_cookies, secure_cookies)
        self.assertEqual(anti_csrf.token_expiry_age, token_expiry_age)
        self.assertEqual(anti_csrf.token_renewal_age, token_renewal_age)


if __name__ == '__main__':
    unittest.main()
