#!/usr/bin/env python
"""SNMP library for Python

   SNMP v1/v2c/v3 engine and apps written in pure-Python.
   Supports Manager/Agent/Proxy roles, scriptable MIBs,
   asynchronous operation and multiple transports.
"""
import sys
import os

classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
Intended Audience :: Education
Intended Audience :: Information Technology
Intended Audience :: System Administrators
Intended Audience :: Telecommunications Industry
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 2
Programming Language :: Python :: 2.4
Programming Language :: Python :: 2.5
Programming Language :: Python :: 2.6
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.2
Programming Language :: Python :: 3.3
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Topic :: Communications
Topic :: System :: Monitoring
Topic :: System :: Networking :: Monitoring
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_setuptools():
    print("""
   Error: You need setuptools Python package!

   It's very easy to install it, just type:

   wget https://bootstrap.pypa.io/ez_setup.py
   python ez_setup.py

   Then you could make eggs from this package.
""")


if sys.version_info[:2] < (2, 4):
    print("ERROR: this package requires Python 2.4 or later!")
    sys.exit(1)

try:
    from setuptools import setup

    params = {
        'install_requires': ['pyasn1>=0.2.3', 'pysmi', 'pycryptodome'],
        'zip_safe': True
    }

except ImportError:
    for arg in sys.argv:
        if 'egg' in arg:
            howto_install_setuptools()
            sys.exit(1)

    from distutils.core import setup

    params = {}
    if sys.version_info[:2] > (2, 4):
        params['requires'] = ['pyasn1(>=0.2.3)', 'pysmi', 'pycryptodome']

doclines = [x.strip() for x in (__doc__ or '').split('\n') if x]

params.update({
    'name': 'pysnmp',
    'version': open(os.path.join('pysnmp', '__init__.py')).read().split('\'')[1],
    'description': doclines[0],
    'long_description': ' '.join(doclines[1:]),
    'maintainer': 'Ilya Etingof <etingof@gmail.com>',
    'author': 'Ilya Etingof',
    'author_email': 'etingof@gmail.com',
    'url': 'https://github.com/etingof/pysnmp',
    'classifiers': [x for x in classifiers.split('\n') if x],
    'platforms': ['any'],
    'license': 'BSD',
    'packages': ['pysnmp',
                 'pysnmp.smi',
                 'pysnmp.smi.mibs',
                 'pysnmp.smi.mibs.instances',
                 'pysnmp.carrier',
                 'pysnmp.carrier.asynsock',
                 'pysnmp.carrier.asynsock.dgram',
                 'pysnmp.carrier.asyncore',
                 'pysnmp.carrier.asyncore.dgram',
                 'pysnmp.carrier.twisted',
                 'pysnmp.carrier.twisted.dgram',
                 'pysnmp.carrier.asyncio',
                 'pysnmp.carrier.asyncio.dgram',
                 'pysnmp.entity',
                 'pysnmp.entity.rfc3413',
                 'pysnmp.entity.rfc3413.oneliner',
                 'pysnmp.hlapi',
                 'pysnmp.hlapi.asyncio',
                 'pysnmp.hlapi.asyncore',
                 'pysnmp.hlapi.asyncore.sync',
                 'pysnmp.hlapi.asyncore.sync.compat',
                 'pysnmp.hlapi.twisted',
                 'pysnmp.proto',
                 'pysnmp.proto.mpmod',
                 'pysnmp.proto.secmod',
                 'pysnmp.proto.secmod.rfc3414',
                 'pysnmp.proto.secmod.rfc3414.auth',
                 'pysnmp.proto.secmod.rfc3414.priv',
                 'pysnmp.proto.secmod.rfc3826',
                 'pysnmp.proto.secmod.rfc3826.priv',
                 'pysnmp.proto.secmod.eso',
                 'pysnmp.proto.secmod.eso.priv',
                 'pysnmp.proto.acmod',
                 'pysnmp.proto.proxy',
                 'pysnmp.proto.api']
})

setup(**params)
