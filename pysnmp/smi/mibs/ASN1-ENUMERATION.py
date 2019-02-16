#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This module supplies built-in ASN.1 types to the MIBs importing it.
#
from pyasn1.type import namedval

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

mibBuilder.exportSymbols(
    'ASN1-ENUMERATION',
    NamedValues=namedval.NamedValues
)
