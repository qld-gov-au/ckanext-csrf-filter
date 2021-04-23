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

1. Restart CKAN. Eg if you've deployed CKAN with Apache on Ubuntu:

    ```
    sudo service apache2 reload
    ```

Configuration
=============

No configuration entries are necessary.

Optional
--------

    # Maximum age of a token cookie. Tokens older than this will be rejected.
    ckanext.csrf_filter.token_expiry_age

    # Tokens older than this will be replaced with new ones on the next response.
    ckanext.csrf_filter.token_rotation_age

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

    1. Run ``nosetests``