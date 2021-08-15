# encoding: utf-8
""" Injects and validates form tokens to prevent Cross-Site Request Forgery attacks.
"""

from logging import getLogger

from ckan.plugins import toolkit, SingletonPlugin, implements, \
    IConfigurable, IRoutes, IBlueprint, IMiddleware

from ckanext.csrf_filter import anti_csrf


if toolkit.check_ckan_version(min_version='2.8.0'):
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


class CSRFFilterPlugin(SingletonPlugin):
    """ Inject CSRF tokens into HTML responses,
    and validate them on applicable requests.
    """
    implements(IConfigurable, inherit=True)
    implements(IRoutes, inherit=True)
    if toolkit.check_ckan_version(min_version='2.8.0'):
        implements(IBlueprint, inherit=True)
        implements(IMiddleware, inherit=True)

    # IConfigurable

    def configure(self, config):
        """ Provide configuration (eg max token age) to the CSRF filter.
        """
        self.config = config
        anti_csrf.configure(config)

    # IRoutes

    def after_map(self, route_map):
        """ Monkey-patch Pylons after routing is set up.
        """
        try:
            from ckanext.csrf_filter import anti_csrf_pylons
            anti_csrf_pylons.intercept()
        except Exception:
            LOG.warn("Unable to load Pylons support. Pylons routes will not be protected.")

        return route_map

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
                toolkit.abort(403, "Your form submission could not be validated")

        @blueprint.after_app_request
        def set_csrf_token(response):
            """ Apply a CSRF token to all response bodies.
            """
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
