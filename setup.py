#!/usr/bin/env python

from distutils.core import setup

setup(name="pysnmp",
      version="3.5.1",
      description="Python SNMP Toolkit",
      author="Ilya Etingof",
      author_email="ilya@glas.net ",
      url="http://sourceforge.net/projects/pysnmp/",
      packages = [ 'pysnmp',
                   'pysnmp.asn1',
                   'pysnmp.asn1.encoding',
                   'pysnmp.asn1.encoding.ber',
                   'pysnmp.proto',
                   'pysnmp.proto.api',
                   'pysnmp.proto.api.alpha',
                   'pysnmp.proto.api.generic',
                   'pysnmp.test',
                   'pysnmp.mapping',
                   'pysnmp.mapping.udp',
                   'pysnmp.smi',
                   'pysnmp.smi.macro',
                   'pysnmp.compat',
                   'pysnmp.compat.pysnmp1x',
                   'pysnmp.compat.pysnmp2x',
                   'pysnmp.compat.snmpy' ],
      license="BSD"
      )
