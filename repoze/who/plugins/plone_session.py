from codecs import utf_8_encode

from paste.request import get_cookies
from plone.session.tktauth import validateTicket, createTicket
from repoze.who.interfaces import IIdentifier, IAuthenticator
from zope.interface import implements

import binascii


class PloneSessionTktPlugin(object):

    implements(IIdentifier, IAuthenticator)

    def __init__(self, secret, cookie_name='auth_tkt',
                 include_ip=False, timeout=None, enhanced_hashing=True):
        self.secret = secret
        self.cookie_name = cookie_name
        self.include_ip = include_ip
        self.timeout = timeout
        self.enhanced_hashing = enhanced_hashing

    # IIDentifier
    def identify(self, environ):
        import pdb;pdb.set_trace()
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)

        if cookie is None or not cookie.value:
            return None

        try:
            tkt = binascii.a2b_base64(cookie.value)
        except binascii.Error:
            return None

        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        validation = validateTicket(self.secret, tkt, remote_addr,
                                    timeout=self.timeout,
                                    mod_auth_tkt=not self.enhanced_hashing)
        if validation:
            ignore, userid, tokens, user_data, timestamp = validation
        else:
            return None

        if cookie is None or not cookie.value:
            return None

        identity = {}
        identity['timestamp'] = timestamp
        identity['repoze.who.plugins.plone_session_tkt.userid'] = userid
        identity['tokens'] = tokens
        identity['userdata'] = user_data
        return identity

    # IIdentifier
    def forget(self, environ, identity):
        return self._get_cookies(environ, 'INVALID', 0)

    # IIdentifier
    def remember(self, environ, identity):
        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        cookies = get_cookies(environ)
        old_cookie = cookies.get(self.cookie_name)
        existing = cookies.get(self.cookie_name)
        old_cookie_value = getattr(existing, 'value', None)

        timestamp, userid, tokens, userdata = None, '', (), ''

        if old_cookie_value:
            validation = validateTicket(self.secret, old_cookie_value,
                                        remote_addr, timeout=self.timeout,
                                        mod_auth_tkt=not self.enhanced_hashing)
            if validation:
                ignore, userid, tokens, user_data, timestamp = validation
            else:
                return
        tokens = tuple(tokens)

        who_userid = identity['repoze.who.userid']
        who_tokens = tuple(identity.get('tokens', ()))
        who_userdata = identity.get('userdata', '')

        who_userid = utf_8_encode(who_userid)[0]

        old_data = (userid, tokens, userdata)
        new_data = (who_userid, who_tokens, who_userdata)

    # IAuthenticator
    def authenticate(self, environ, identity):
        userid = identity.get('repoze.who.plugins.plone_session_tkt.userid')
        if userid is None:
            return None
        identity['repoze.who.userid'] = userid
        return userid

    def _get_cookies(self, environ, value):
        max_age = ''

        cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
        wild_domain = '.' + cur_domain
        cookies = [
            ('Set-Cookie', '%s="%s"; Path=/%s%s' % (
            self.cookie_name, value, max_age, secure)),
            ('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
            self.cookie_name, value, cur_domain, max_age, secure)),
            ('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
            self.cookie_name, value, wild_domain, max_age, secure))
            ]
        return cookies

def _bool(value):
    if isinstance(value, basestring):
        return value.lower() in ('yes', 'true', '1')
    return value

def make_plugin(secret=None,
                cookie_name='auth_tkt',
                include_ip=False,
                timeout=None,
                enhanced_hashing=True
               ):
    from repoze.who.utils import resolveDotted
    if (secret is None):
        raise ValueError("'secret' must not be None.")
    if timeout:
        timeout = int(timeout)
    plugin = PloneSessionTktPlugin(secret,
                                   cookie_name,
                                   _bool(include_ip),
                                   timeout,
                                   _bool(enhanced_hashing)
                                   )
    return plugin
