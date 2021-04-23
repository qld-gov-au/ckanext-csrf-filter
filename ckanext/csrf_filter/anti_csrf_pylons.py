# encoding: utf-8
""" Deprecated - remove after Pylons-based routing is extinct.

CKAN 2.9 moved most requests to Flask, which has a much cleaner system of
request hooks, but it still supports Pylons for backwards compatibility with
plugins.

Hook the CSRF filter into Pylons.
"""
from ckan.common import response
from ckan.lib import base

import anti_csrf


RAW_RENDER_JINJA = base.render_jinja2
RAW_BEFORE = base.BaseController.__before__


def _render_jinja(template_name, extra_vars=None):
    """ Wrap the Jinja rendering function to inject tokens on HTML responses.
    """
    return anti_csrf.apply_token(RAW_RENDER_JINJA(template_name, extra_vars), response)


def _before_controller(obj, action, **params):
    """ Wrap the core pre-action function to require tokens on applicable requests.
    """
    RAW_BEFORE(obj, action)

    anti_csrf.check_csrf()


def intercept():
    """ Monkey-patch Pylons functions to add CSRF checks.
    """
    base.render_jinja2 = _render_jinja
    base.BaseController.__before__ = _before_controller
