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

(pysnmpUsmDiscoverable,
 pysnmpUsmDiscovery) = mibBuilder.importSymbols(
    'PYSNMP-USM-MIB',
    'pysnmpUsmDiscoverable',
    'pysnmpUsmDiscovery'
)

_pysnmpUsmDiscoverable = MibScalarInstance(
    pysnmpUsmDiscoverable.name, (0,),
    pysnmpUsmDiscoverable.syntax
)

_pysnmpUsmDiscovery = MibScalarInstance(
    pysnmpUsmDiscovery.name, (0,),
    pysnmpUsmDiscovery.syntax
)

mibBuilder.exportSymbols(
    "__PYSNMP-USM-MIB",
    pysnmpUsmDiscoverable=_pysnmpUsmDiscoverable,
    pysnmpUsmDiscovery=_pysnmpUsmDiscovery
)
