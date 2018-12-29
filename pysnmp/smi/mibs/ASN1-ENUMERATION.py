#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.type import namedval

mibBuilder.exportSymbols(
    'ASN1-ENUMERATION',
    NamedValues=namedval.NamedValues
)
