#!/usr/bin/env python
"""SNMP library for Python

SNMP v1/v2c/v3 engine and Standard Applications suite written in pure-Python.
Supports Manager/Agent/Proxy roles, Manager/Agent-side MIBs, asynchronous
operation and multiple network transports.
"""
import os
import re
import sys

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
Programming Language :: Python :: 2.6
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.2
Programming Language :: Python :: 3.3
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Programming Language :: Python :: 3.7
Topic :: Communications
Topic :: System :: Monitoring
Topic :: System :: Networking :: Monitoring
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_setuptools():
    print("""\
Error: You need setuptools Python package!

It's very easy to install it, just type:

wget https://bootstrap.pypa.io/ez_setup.py
python ez_setup.py

Then you could make eggs from this package.
""")


py_version = sys.version_info[:2]
if py_version < (2, 6):
    print("ERROR: this package requires Python 2.6 or later!")
    sys.exit(1)

requires = [ln.strip() for ln in open('requirements.txt').readlines()]

resolved_requires = []

for requirement in requires:
    match = re.match(
        r'(.*?)\s*;\s*python_version\s*([<>=!~]+)\s*\'(.*?)\'', requirement)

    if not match:
        resolved_requires.append(requirement)
        continue

    package, condition, expected_py = match.groups()

    expected_py = tuple([int(x) for x in expected_py.split('.')])

    if py_version == expected_py and condition in ('<=', '==', '>='):
        resolved_requires.append(package)

    elif py_version < expected_py and condition in ('<=', '<'):
        resolved_requires.append(package)

    elif py_version > expected_py and condition in ('>=', '>'):
        resolved_requires.append(package)

try:
    import setuptools

    setup, Command = setuptools.setup, setuptools.Command

    observed_version = [int(x) for x in setuptools.__version__.split('.')[:3]]
    required_version = [36, 2, 0]

    # NOTE(etingof): require fresh setuptools to build proper wheels
    # See also: https://hynek.me/articles/conditional-python-dependencies/
    if ('bdist_wheel' in sys.argv and
            observed_version < required_version):
        print("ERROR: your wheels won't come out round with setuptools %s! "
              "Upgrade to %s and try again." % (
                '.'.join(str(x) for x in observed_version),
                '.'.join(str(x) for x in required_version)))
        sys.exit(1)

    # NOTE(etingof): older setuptools fail at parsing python_version

    if observed_version < required_version:
        requires = resolved_requires

    params = {
        'install_requires': requires,
        'zip_safe': True
    }

except ImportError:
    if 'bdist_wheel' in sys.argv or 'bdist_egg' in sys.argv:
        howto_install_setuptools()
        sys.exit(1)

    from distutils.core import setup

    params = {}

    if py_version > (2, 4):
        params['requires'] = [
            re.sub(r'(.*?)([<>=!~]+)(.*)', r'\g<1>\g<2>(\g<3>)', r) for r in resolved_requires
        ]

doclines = [x.strip() for x in (__doc__ or '').split('\n')]

params.update({
    'name': 'pysnmp',
    'version': open(os.path.join('pysnmp', '__init__.py')).read().split('\'')[1],
    'description': doclines[0],
    'long_description': '\n'.join(doclines[1:]),
    'maintainer': 'Ilya Etingof <etingof@gmail.com>',
    'author': 'Ilya Etingof',
    'author_email': 'etingof@gmail.com',
    'url': 'https://github.com/etingof/pysnmp',
    'classifiers': [x for x in classifiers.split('\n') if x],
    'platforms': ['any'],
    'license': 'BSD-2-Clause',
    'packages': ['pysnmp',
                 'pysnmp.smi',
                 'pysnmp.smi.mibs',
                 'pysnmp.smi.mibs.instances',
                 'pysnmp.carrier',
                 'pysnmp.carrier.asyncore',
                 'pysnmp.carrier.asyncore.dgram',
                 'pysnmp.carrier.twisted',
                 'pysnmp.carrier.twisted.dgram',
                 'pysnmp.carrier.asyncio',
                 'pysnmp.carrier.asyncio.dgram',
                 'pysnmp.entity',
                 'pysnmp.entity.rfc3413',
                 'pysnmp.hlapi',
                 'pysnmp.hlapi.v1arch',
                 'pysnmp.hlapi.v1arch.asyncio',
                 'pysnmp.hlapi.v1arch.asyncore',
                 'pysnmp.hlapi.v1arch.asyncore.sync',
                 'pysnmp.hlapi.v3arch',
                 'pysnmp.hlapi.v3arch.asyncio',
                 'pysnmp.hlapi.v3arch.asyncore',
                 'pysnmp.hlapi.v3arch.asyncore.sync',
                 'pysnmp.hlapi.v3arch.twisted',
                 'pysnmp.proto',
                 'pysnmp.proto.mpmod',
                 'pysnmp.proto.secmod',
                 'pysnmp.proto.secmod.rfc3414',
                 'pysnmp.proto.secmod.rfc3414.auth',
                 'pysnmp.proto.secmod.rfc3414.priv',
                 'pysnmp.proto.secmod.rfc3826',
                 'pysnmp.proto.secmod.rfc3826.priv',
                 'pysnmp.proto.secmod.rfc7860',
                 'pysnmp.proto.secmod.rfc7860.auth',
                 'pysnmp.proto.secmod.eso',
                 'pysnmp.proto.secmod.eso.priv',
                 'pysnmp.proto.acmod',
                 'pysnmp.proto.proxy',
                 'pysnmp.proto.api']
})

setup(**params)
