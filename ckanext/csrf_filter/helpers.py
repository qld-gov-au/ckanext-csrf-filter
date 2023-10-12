from markupsafe import Markup
from ckanext.csrf_filter.anti_csrf import get_response_token, TOKEN_FIELD_NAME

try:
    from ckan.common import is_flask_request
except ImportError:
    def is_flask_request():
        return True


def csrf_token_field():
    if is_flask_request():
        from flask import Response
        response = Response()
    else:
        from pylons import response
    token = get_response_token(response)
    return Markup('<input type="hidden" name="{}" value="{}"/>'.format(TOKEN_FIELD_NAME, token))
