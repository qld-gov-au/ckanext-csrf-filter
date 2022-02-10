# encoding: utf-8

''' Tests that the Repoze plugin filters Login CSRF properly.
'''

import unittest

from ckanext.csrf_filter import anti_csrf
from ckanext.csrf_filter import token_protected_friendlyform
import six


class TestAntiCsrfFilter(unittest.TestCase):
    """ Test our anti-CSRF filter with mock CKAN objects.
    """

    def _setUp(self):
        anti_csrf.configure({
            'ckanext.csrf_filter.secret_key': 'secret',
            'ckan.site_url': 'https://localhost/unit-test'})
        self.plugin = token_protected_friendlyform.TokenProtectedFriendlyFormPlugin(
            login_form_url="/user/login", login_handler_path="/login_generic",
            post_login_url="/user/logged_in", logout_handler_path="/user/logout",
            post_logout_url="/user/logged_out", rememberer_name="auth_tkt")
        self.environ = {
            'REQUEST_METHOD': 'POST',
            'PATH_INFO': '/login_generic',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '80',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'wsgi.url_scheme': 'http',
            'wsgi.input': six.BytesIO(),
            'wsgi.errors': six.BytesIO()
        }

    def test_accepts_valid_token(self):
        """ Test that the plugin accepts valid requests.
        """
        self._setUp()
        token_expression = 'token=' + anti_csrf.create_response_token()
        self.environ['HTTP_COOKIE'] = token_expression
        self._set_request_body(token_expression)
        self._check_csrf(True)

    def test_rejects_missing_token(self):
        """ Test that the plugin rejects requests without a token.
        """
        self._setUp()
        self._check_csrf(False)

    def test_rejects_invalid_token(self):
        """ Test that the plugin rejects requests with invalid tokens.
        """
        self._setUp()
        token_expression = 'token=' + anti_csrf.create_response_token()
        self.environ['HTTP_COOKIE'] = token_expression
        self._set_request_body('token=foo')
        self._check_csrf(False)

    def test_ignores_token_outside_login(self):
        """ Test that the plugin ignores tokens when not logging in.
        """
        self._setUp()
        self.environ['PATH_INFO'] = '/foo'
        self._check_csrf(True)

    def _set_request_body(self, body):
        self.environ['wsgi.input'] = six.BytesIO(body)
        self.environ['CONTENT_LENGTH'] = len(body)

    def _check_csrf(self, expect_success):
        if expect_success:
            self.assertTrue(self.plugin._check_csrf(self.environ))
        else:
            self.assertFalse(self.plugin._check_csrf(self.environ))


if __name__ == '__main__':
    unittest.main()
