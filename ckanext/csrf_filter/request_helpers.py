# encoding: utf-8
""" Some useful functions for interacting with the current request.
"""


class RequestHelper():

    def __init__(self, request=None):
        if request:
            self.request = request
        else:
            from ckan.plugins import toolkit
            self.request = toolkit.request

    def get_path(self):
        """ Get the request path, without query string.
        """
        return self.request.path

    def get_method(self):
        """ Get the request method, eg HEAD, GET, POST.
        """
        return self.request.method

    def get_environ(self):
        """ Get the WebOb environment dict.
        """
        return self.request.environ

    def get_cookie(self, field_name, default=None):
        """ Get the value of a cookie, or the default value if not present.
        """
        return self.request.cookies.get(field_name, default)

    def get_post_params(self, field_name):
        """ Retrieve a list of all POST parameters with the specified name
        for the current request.

        This uses 'request.form' for Flask.
        """
        return self.request.form.getlist(field_name)

    def get_query_params(self, field_name):
        """ Retrieve a list of all GET parameters with the specified name
        for the current request.

        This uses 'request.args' for Flask.
        """
        return self.request.args.getlist(field_name)

    def delete_param(self, field_name):
        """ Remove the parameter with the specified name from the current
        request. This requires the request parameters to be mutable.
        """
        for collection_name in ['args', 'form', 'GET', 'POST']:
            collection = getattr(self.request, collection_name, {})
            if field_name in collection:
                del collection[field_name]

    def scoped_attrs(self):
        """ Returns a mutable dictionary of attributes that exist in the
        scope of the current request, and will vanish afterward.
        """
        if 'webob.adhoc_attrs' not in self.request.environ:
            self.request.environ['webob.adhoc_attrs'] = {}
        return self.request.environ['webob.adhoc_attrs']
