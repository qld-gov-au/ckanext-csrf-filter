from flask import Response
from markupsafe import Markup
from ckanext.csrf_filter.anti_csrf import get_response_token, TOKEN_FIELD_NAME

def csrf_token_field():
    token = get_response_token(Response())
    return Markup('<input type="hidden" name="{}" value="{}"/>'.format(TOKEN_FIELD_NAME, token))
