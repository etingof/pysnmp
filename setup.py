#!/usr/bin/env python
import sys
import string

def howto_install_setuptools():
    print """Error: You need setuptools Python package!

It's very easy to install it, just type (as root on Linux):
   wget http://peak.telecommunity.com/dist/ez_setup.py
   python ez_setup.py
"""

try:
    from setuptools import setup
    params = {
        'install_requires': [ 'pyasn1', 'pycrypto' ],
        'provides': [ 'pysnmp' ],
        'zip_safe': True
        }
except ImportError:
    for arg in sys.argv:
        if string.find(arg, 'egg') != -1:
            howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup
    if sys.version_info > (2, 2):
        params = {
            'requires': [ 'pyasn1', 'pycrypto' ],
            'provides': [ 'pysnmp' ]
        }
    else:
        params = {}

params.update( {
    'name': 'pysnmp',
    'version': '4.1.15a',
    'description': 'SNMP framework',
    'author': 'Ilya Etingof',
    'author_email': 'ilya@glas.net',
    'url': 'http://sourceforge.net/projects/pysnmp/',
    'license': 'BSD',
    'packages': [ 'pysnmp',
                  'pysnmp.smi',
                  'pysnmp.smi.mibs',
                  'pysnmp.smi.mibs.instances',
                  'pysnmp.carrier',
                  'pysnmp.carrier.asynsock',
                  'pysnmp.carrier.asynsock.dgram',
                  'pysnmp.carrier.twisted',
                  'pysnmp.carrier.twisted.dgram',                   
                  'pysnmp.entity',
                  'pysnmp.entity.rfc3413',
                  'pysnmp.entity.rfc3413.oneliner',
                  'pysnmp.entity.rfc3413.twisted',
                  'pysnmp.proto',
                  'pysnmp.proto.mpmod',
                  'pysnmp.proto.secmod',
                  'pysnmp.proto.secmod.rfc3414',
                  'pysnmp.proto.secmod.rfc3414.auth',
                  'pysnmp.proto.secmod.rfc3414.priv',
                  'pysnmp.proto.secmod.rfc3826',
                  'pysnmp.proto.secmod.rfc3826.priv',
                  'pysnmp.proto.acmod',
                  'pysnmp.proto.proxy',
                  'pysnmp.proto.api' ],
    'scripts': [ 'tools/libsmi2pysnmp', 'tools/build-pysnmp-mib' ]
    } )

apply(setup, (), params)

