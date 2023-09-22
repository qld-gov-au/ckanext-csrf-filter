from ckanext.csrf_filter.anti_csrf import get_response_token, TOKEN_FIELD_NAME

def csrf_token_field():
    # TODO: try to pass the response object into get_response_token
    token = get_response_token({})
    return '<input type="hidden" name="{}" value="{}"/>'.format(TOKEN_FIELD_NAME, token)
