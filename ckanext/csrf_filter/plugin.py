# encoding: utf-8
""" Injects and validates form tokens to prevent Cross-Site Request Forgery attacks.
"""

from logging import getLogger
from types import GeneratorType

from ckan import plugins
from ckan.plugins import implements, toolkit

from ckanext.csrf_filter import anti_csrf
import ckanext.csrf_filter.helpers as h
from ckanext.csrf_filter.request_helpers import RequestHelper


from flask import Blueprint, Request
from werkzeug.datastructures import MultiDict, ImmutableMultiDict


class MostlyImmutableMultiDict(ImmutableMultiDict):
    """ Allows a single mutating operation, to delete the CSRF token.
    """
    mutable_fields = [anti_csrf.TOKEN_FIELD_NAME]

    def __delitem__(self, key):
        if key in self.mutable_fields:
            return MultiDict.__delitem__(self, key)
        else:
            return super.__delitem__(key)


class CSRFAwareRequest(Request):
    """ Adjust parameter storage so we can delete CSRF tokens.
    """
    parameter_storage_class = MostlyImmutableMultiDict


LOG = getLogger(__name__)


class CSRFFilterPlugin(plugins.SingletonPlugin):
    """ Inject CSRF tokens into HTML responses,
    and validate them on applicable requests.
    """
    implements(plugins.IConfigurer)
    implements(plugins.IConfigurable, inherit=True)
    implements(plugins.IAuthenticator, inherit=True)
    implements(plugins.ITemplateHelpers)
    implements(plugins.IBlueprint, inherit=True)
    implements(plugins.IMiddleware, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

    # IConfigurable

    def configure(self, config):
        """ Provide configuration (eg max token age) to the CSRF filter.
        """
        self.config = config
        anti_csrf.configure(config)

    # IAuthenticator

    def login(self):
        request = RequestHelper()
        request.get_environ()['__no_cache__'] = True
        return None

    # ITemplateHelpers

    def get_helpers(self):
        return {'csrf_token_field': h.csrf_token_field}

    # IBlueprint

    def get_blueprint(self):
        """ Create a blueprint that uses a Flask rule to intercept all
        requests and set/check CSRF tokens.
        """

        blueprint = Blueprint(self.name, self.__module__)

        @blueprint.before_app_request
        def check_csrf():
            """ Abort invalid Flask requests based on CSRF token.
            """
            if not anti_csrf.check_csrf():
                return toolkit.abort(403, "Your form submission could not be validated")

        @blueprint.after_app_request
        def set_csrf_token(response):
            """ Apply a CSRF token to all response bodies.

            Exclude GeneratorType responses as they are data streams.
            Modifying the data of the data stream breaks the streaming process.

            If a user needs to stream templates, they should use the csrf_token_field
            helper in their forms inside of their streamed templates.
            """
            if isinstance(getattr(response, 'response', None), GeneratorType):
                return response

            response.direct_passthrough = False
            anti_csrf.apply_token(response)
            return response

        return blueprint

    # IMiddleware

    def make_middleware(self, app, config):
        """ Configure the Flask app to permit deletion of the CSRF token
        from the request parameters. Otherwise the token ends up getting
        populated in dataset and resource 'extras'.
        """
        if hasattr(app, 'request_class'):
            app.request_class = CSRFAwareRequest
            if app.secret_key:
                self.config['flask.secret_key'] = app.secret_key
                anti_csrf.configure(self.config)

        return app
