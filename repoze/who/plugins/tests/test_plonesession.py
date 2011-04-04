
import unittest


class TestPloneSessionTktPlugin(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.who.plugins.plonesession_tkt import PloneSessionTktPlugin
        return PloneSessionTktPlugin

    def _makeOne(self, secret='geheim', *args, **kwargs):
        plugin = self._getTargetClass()(secret, *args, **kwargs)
        return plugin

    def _makeEnviron(self, kw=None):
        environ = {'wsgi.version': (1, 0)}
        if kw is not None:
            environ.update(kw)
        environ['REMOTE_ADDR'] = '1.1.1.1'
        environ['SERVER_NAME'] = 'localhost'
        return environ

    def _makeTicket(self, userid='userid', remote_addr='0.0.0.0',
                    tokens=tuple(), userdata='userdata',
                    cookie_name='auth_tkt', enhanced_hashing=True,
                    time=None):
        import binascii
        from plone.session.tktauth import createTicket
        tkt = createTicket('secret', userid, tokens, userdata, ip=remote_addr,
                     timestamp=time, mod_auth_tkt=enhanced_hashing)
        return binascii.b2a_base64(tkt).strip()

    def test_class_conforms_to_IIdentifier(self):
        from repoze.who.interfaces import IIdentifier
        from zope.interface.verify import verifyClass
        klass = self._getTargetClass()
        verifyClass(IIdentifier, klass)

    def test_instance_conforms_to_IIdentifier(self):
        from zope.interface.verify import verifyObject
        from repoze.who.interfaces import IIdentifier
        klass = self._getTargetClass()
        verifyObject(IIdentifier, self._makeOne())

    def test_class_conforms_to_IAuthenticator(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyClass(IAuthenticator, klass)

    def test_instance_conforms_to_IAuthenticator(self):
        from zope.interface.verify import verifyObject
        from repoze.who.interfaces import IAuthenticator
        klass = self._getTargetClass()
        verifyObject(IAuthenticator, self._makeOne())

    def test_identify_nocookie(self):
        plugin = self._makeOne('secret')
        environ = self._makeEnviron()
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_identify_good_cookie_include_ip(self):
        plugin = self._makeOne('secret', include_ip=True)
        val = self._makeTicket(remote_addr='1.1.1.1')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], tuple())
        self.assertEqual(result['repoze.who.plugins.plone_session_tkt.userid'],
                         'userid')
        self.assertEqual(result['userdata'], 'userdata')
        self.failUnless('timestamp' in result)

    def test_identify_good_cookie_dont_include_ip(self):
        plugin = self._makeOne('secret', include_ip=False)
        val = self._makeTicket()
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], tuple())
        self.assertEqual(result['repoze.who.plugins.plone_session_tkt.userid'],
                         'userid')
        self.assertEqual(result['userdata'], 'userdata')
        self.failUnless('timestamp' in result)

    def test_identify_good_cookie_honour_hashing(self):
        plugin = self._makeOne('secret', include_ip=False,
                               enhanced_hashing=False)
        val = self._makeTicket()
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(None, result)
        plugin.enhanced_hashing = True
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)

    def test_identify_good_cookie_unknown_useridtype(self):
        plugin = self._makeOne('secret', include_ip=False)
        val = self._makeTicket(userid='userid', userdata='userid_type:unknown')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(len(result), 4)
        self.assertEqual(result['tokens'], tuple())
        self.assertEqual(result['repoze.who.plugins.plone_session_tkt.userid'],
                         'userid')
        self.assertEqual(result['userdata'], 'userid_type:unknown')
        self.failUnless('timestamp' in result)

    def test_identify_bad_cookie(self):
        plugin = self._makeOne('secret', include_ip=True)
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=bogus'})
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_identify_bad_cookie_expired(self):
        import time
        plugin = self._makeOne('secret', timeout=2)
        val = self._makeTicket(userid='userid', time=time.time() - 3)
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.identify(environ)
        self.assertEqual(result, None)

    def test_remember_creds_same(self):
        plugin = self._makeOne('secret')
        val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % val})
        result = plugin.remember(environ, {'repoze.who.userid': 'userid',
                                           'userdata': 'userdata'})
        self.assertEqual(result, None)

    def test_remember_creds_different(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='other', userdata='userdata')
        result = plugin.remember(environ, {'repoze.who.userid': 'other',
                                           'userdata': 'userdata'})
        self.assertEqual(None, result)

    def test_remember_creds_different_include_ip(self):
        plugin = self._makeOne('secret', include_ip=True)
        old_val = self._makeTicket(userid='userid', remote_addr='1.1.1.1')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='other',
                                   userdata='userdata',
                                   remote_addr='1.1.1.1')
        result = plugin.remember(environ, {'repoze.who.userid': 'other',
                                           'userdata': 'userdata'})
        self.assertEqual(None, result)

    def test_remember_creds_different_bad_old_cookie(self):
        plugin = self._makeOne('secret')
        old_val = 'BOGUS'
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='other', userdata='userdata')
        result = plugin.remember(environ, {'repoze.who.userid': 'other',
                                           'userdata': 'userdata'})
        self.assertEqual(None, result)

    def test_remember_creds_different_with_tokens(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='userid',
                                   userdata='userdata',
                                   tokens=['foo', 'bar'],
                                  )
        result = plugin.remember(environ, {'repoze.who.userid': 'userid',
                                           'userdata': 'userdata',
                                           'tokens': ['foo', 'bar'],
                                          })
        self.assertEqual(None, result)

    def test_remember_creds_different_with_tuple_tokens(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='userid',
                                   userdata='userdata',
                                   tokens=['foo', 'bar'],
                                  )
        result = plugin.remember(environ, {'repoze.who.userid': 'userid',
                                           'userdata': 'userdata',
                                           'tokens': ('foo', 'bar'),
                                          })
        self.assertEqual(None, result)

    def test_remember_creds_different_int_userid(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='1', userdata='userid_type:int')
        result = plugin.remember(environ, {'repoze.who.userid': 1,
                                           'userdata': ''})
        self.assertEqual(None, result)

    def test_remember_creds_different_long_userid(self):
        plugin = self._makeOne('secret')
        old_val = self._makeTicket(userid='userid')
        environ = self._makeEnviron({'HTTP_COOKIE': 'auth_tkt=%s' % old_val})
        new_val = self._makeTicket(userid='1', userdata='userid_type:int')
        result = plugin.remember(environ, {'repoze.who.userid': long(1),
                                           'userdata': ''})
        self.assertEqual(None, result)

    def test_authenticate_non_auth_tkt_credentials(self):
        plugin = self._makeOne()
        self.assertEqual(plugin.authenticate(environ={}, identity={}), None)

    def test_authenticate_without_checker(self):
        plugin = self._makeOne()
        identity = {'repoze.who.plugins.plone_session_tkt.userid': 'phred'}
        self.assertEqual(plugin.authenticate({}, identity), 'phred')

    def test_factory_wo_secret_wo_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin)

    def test_factory_w_secret_w_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin, 'secret', 'secretfile')

    def test_factory_w_bad_secretfile_raises_ValueError(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        self.assertRaises(ValueError, make_plugin, secretfile='nonesuch.txt')

    def test_factory_w_secret(self):
        from repoze.who.plugins.auth_tkt import make_plugin
        plugin = make_plugin('secret')
        self.assertEqual(plugin.cookie_name, 'auth_tkt')
        self.assertEqual(plugin.secret, 'secret')
        self.assertEqual(plugin.include_ip, False)
        self.assertEqual(plugin.secure, False)

    def test_factory_w_secretfile(self):
        import os
        from tempfile import mkdtemp
        from repoze.who.plugins.auth_tkt import make_plugin
        tempdir = self.tempdir = mkdtemp()
        path = os.path.join(tempdir, 'who.secret')
        secret = open(path, 'w')
        secret.write('s33kr1t\n')
        secret.flush()
        secret.close()
        plugin = make_plugin(secretfile=path)
        self.assertEqual(plugin.secret, 's33kr1t')
