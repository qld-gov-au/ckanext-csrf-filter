ckanext-csrf-filter
===================

Overview
========
A CKAN extension to add protection against [Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
attacks, with minimal overhead (no server-side state, no modifications to existing forms).

This is achieved using a mix of the Double Submit Cookie and HMAC Based Token
patterns [documented by OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
with tokens being generated from a HMAC of the username, current time, nonce, and a server secret.
Tokens are set in cookies and injected into HTML responses as needed, then verified
on applicable POST requests.

By default, tokens expire after 30 minutes, and will be proactively rotated after 10 minutes.

An attacker restricted by the Same Origin Policy is unable to read or write
the token cookie, and is therefore unable to forge a request that will match it.

An attacker who finds an XSS exploit on a subdomain allowing them to write cookies
will still be unable to write a properly formed token cookie, since it requires
knowledge of the server secret.

Installation
============

To install ``ckanext-csrf-filter``:

1. Install CKAN >=2.8. CKAN 2.7 may be compatible, but is not tested.

1. Activate your CKAN virtual environment, eg:

    ```
    . /usr/lib/ckan/default/bin/activate
    ```

1. Install the extension into your virtual environment:

    ```
    pip install -e git+https://github.com/qld-gov-au/ckanext-csrf-filter.git#egg=ckanext-csrf-filter
    ```

1. Install the extension dependencies:

    ```
    pip install -r ckanext-csrf-filter/requirements.txt
    ```

1. Add ``csrf_filter`` to the ``ckan.plugins`` setting in
your CKAN config file (by default the config file is located at
``/etc/ckan/default/production.ini``).

1. Optional: To prevent [Login CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#login-csrf),
replace the FriendlyForm plugin in `who.ini` with a token-aware version:

    ```
    [plugin:friendlyform]
    #use = repoze.who.plugins.friendlyform:FriendlyFormPlugin
    use = ckanext.csrf_filter.token_protected_friendlyform:TokenProtectedFriendlyFormPlugin
    ```

1. Optional: To set token cookie [SameSite attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value), set ``ckanext.csrf_filter.same_site`` setting in your CKAN config file. By default, the SameSite attribute will be ``None``. Supported values:

    * Strict
    * Lax
    * None

1. Restart CKAN. Eg if you've deployed CKAN with Apache on Ubuntu:

    ```
    sudo service apache2 reload
    ```

Configuration
=============

A cryptographically unguessable server secret must be present to generate secure hashes.
This will be taken from one of the following, in order:

- `ckanext.csrf_filter.secret_key` (if you wish to provide your own key)
- `beaker.session.secret` (normally present within CKAN apps out of the box)
- The Flask app `secret_key` value (for future-proofing and easier conversion to non-CKAN applications)

The value of `ckan.site_url` will be used to determine whether token cookies
should have the 'Secure' flag. NB Insecure cookies should only be used in testing,
never in a production environment.

Optional
--------

    # Maximum age of a token cookie, in minutes.
    # Tokens older than this will be rejected.
    # Default 30 minutes.
    ckanext.csrf_filter.token_expiry_minutes = 30

    # Tokens older than this will be replaced with new ones on the next response.
    # Default 10 minutes.
    ckanext.csrf_filter.token_rotation_minutes = 10


Testing
=======

To run the tests:

1. Activate your CKAN virtual environment, eg:

    ```
    . /usr/lib/ckan/default/bin/activate
    ```

1. Switch to the extension directory, eg:

    ```
    cd /usr/lib/ckan/default/src/ckanext-csrf-filter
    ```

1. Run the tests. This can be done in multiple ways.

    1. Execute the test class directly:

        ```
        python ckanext/csrf_filter/test_anti_csrf.py
        ```

    1. Run ``nosetests`` or ``pytest``.
