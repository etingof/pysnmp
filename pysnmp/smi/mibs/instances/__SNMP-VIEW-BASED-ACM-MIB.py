#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This file instantiates some of the MIB managed objects for SNMP engine use
#

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

MibScalarInstance, = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibScalarInstance'
)

vacmViewSpinLock, = mibBuilder.importSymbols(
    'SNMP-VIEW-BASED-ACM-MIB',
    'vacmViewSpinLock'
)

_vacmViewSpinLock = MibScalarInstance(
    vacmViewSpinLock.name, (0,),
    vacmViewSpinLock.syntax
)

mibBuilder.exportSymbols(
    "__SNMP-VIEW-BASED-ACM-MIB",
    vacmViewSpinLock=_vacmViewSpinLock
)
