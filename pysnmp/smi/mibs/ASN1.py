#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This module supplies built-in ASN.1 types to the MIBs importing it.
#
from pysnmp.proto import rfc1902

from pyasn1.type import univ

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

mibBuilder.exportSymbols(
    'ASN1',
    ObjectIdentifier=univ.ObjectIdentifier,
    # Instead of using base ASN,1 types we use SNMPv2 SMI ones to make
    # SMI objects type-compatible with SNMP protocol values
    Integer=rfc1902.Integer32,
    OctetString=rfc1902.OctetString
)
