#!/usr/bin/env python

from distutils.core import setup

setup(name="pysnmp",
      version="4.0.0-alpha",
      description="SNMP framework for Python",
      author="Ilya Etingof",
      author_email="ilya@glas.net ",
      url="http://sourceforge.net/projects/pysnmp/",
      packages = [ 'pysnmp',
                   'pysnmp.asn1',
                   'pysnmp.asn1.encoding',
                   'pysnmp.asn1.encoding.ber',
                   'pysnmp.smi',
                   'pysnmp.smi.mibs',
                   'pysnmp.carrier',
                   'pysnmp.carrier.asynsock',
                   'pysnmp.carrier.asynsock.dgram',
                   'pysnmp.proto',
                   'pysnmp.proto.msgproc',
                   'pysnmp.proto.secmod',
                   'pysnmp.proto.api',
                   'pysnmp.proto.api.alpha' ],
      license="BSD"
      )
