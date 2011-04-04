import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

setup(name='repoze.who.plugins.plonesession_tkt',
      version='0.1',
      description=('repoze.who.plugins.plonesession_tkt offers an '
                   'identificator plugin that understands cookies made '
                   'with plone session. It enables one to implement identify '
                   'users that already logged in in Plone.'),
      long_description='\n\n'.join([README, CHANGES]),
      classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      keywords='web application server wsgi zope',
      author="Patrick Gerken",
      author_email="do3cc@patrick-gerken.de",
      url="http://www.patrick-gerken.de",
      license="BSD",
      packages=find_packages(),
      include_package_data=True,
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      zip_safe=False,
      tests_require=['Paste', 'zope.interface'],
      install_requires=['Paste', 'zope.interface', 'setuptools',
                        'plone.session', 'repoze.who'],
      test_suite="repoze.who.plugins.tests",
      entry_points="""\
      """
)

