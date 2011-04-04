Repoze.who plugin for cookie identification and authorization
=============================================================

repoze.who already contains a cookie plugin. This one is different.
The cookies can be compatible to the ones created by ``mod_auth_tkt`` from
apache, and they can be compatible to ``plone.session``.

This allows for easy Single Sign own between a wsgi app that uses
repoze.who and ``Plone``.

.. _mod_auth_tkt: http://www.openfusion.com.au/labs/mod_auth_tkt/
.. _plone_session: http://pypi.python.org/plone.session/
.. _Plone: http://www.plone.org/

The code is a minimal working version. Some features have been stripped:

- We do not reissue cookies
  If the timeout is reached, users get logged out.
- We do not validate users further
  If the secret isn't one can impersonate as another user. We do not
  check users further and there is no way to change that like there
  is in the original plugin. The only reason we removed this option
  was to avoid procrastination by trying "quickly" write a userid
  validator that looks into plone.
- We do not support non ascii user ids
- Wo do not give cookies a max age
  Cookies should get deleted on browser close anyway. With the
  optional timeout parameter we kill outdated cookies server side.
- We do not allow to restrict cookies to be transmitted securely only
- We do never ever generate new cookies.

In summary, this package needs some work for production use, or you
must evaluate whether these constraints are an issue for your site.

Using repoze.whoplugins.plone_session
=====================================
Configuration works similar to the auth_tkt plugin. Please consult the
``original repoze.who documentation`` for configuring plugins.

For the plone_session you have the following configuration parameters:

- secret
  The secret to use for hashing the cookie. Keep it secret.

- cookie_name
  The name that the authorization cookie should have

- include_ip
  Whether the cookie should contain the ip.
  Note::

        Using the include_ip setting for public-facing applications
        may cause problems for some users. One study reports that as
        many as 3% of users change their IP addresses legitimately
        during a session.

- timeout
  A timeout in seconds after which a cookie becomes invalid.

- enhanced_hashing
  The original mod_auth_tkt cookie uses a somewhat old hashing
  algorithms. Plone uses the newer sha256 hashing algorithm. Setting
  enhanced_hashing to true, will also make use of that algorithm


.. _original repoze.who documentation:
http://docs.repoze.org/who/2.0/configuration.html

How to use this plugin with Plone
=================================
In your plone site, go to XXX and set a secret.
use the same secret in the plugin configuration.
In the plugin configuration, set the cookie_name to __ac and the
enhanced_hashing to true. Now you are good to go.
