#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
MibScalarInstance, = mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalarInstance')

(pysnmpUsmDiscoverable,
 pysnmpUsmDiscovery,
 pysnmpUsmKeyType) = mibBuilder.importSymbols(
    'PYSNMP-USM-MIB',
    'pysnmpUsmDiscoverable',
    'pysnmpUsmDiscovery',
    'pysnmpUsmKeyType'
)

__pysnmpUsmDiscoverable = MibScalarInstance(pysnmpUsmDiscoverable.name, (0,), pysnmpUsmDiscoverable.syntax)
__pysnmpUsmDiscovery = MibScalarInstance(pysnmpUsmDiscovery.name, (0,), pysnmpUsmDiscovery.syntax)
__pysnmpUsmKeyType = MibScalarInstance(pysnmpUsmKeyType.name, (0,), pysnmpUsmKeyType.syntax)

mibBuilder.exportSymbols(
    "__PYSNMP-USM-MIB",
    pysnmpUsmDiscoverable=__pysnmpUsmDiscoverable,
    pysnmpUsmDiscovery=__pysnmpUsmDiscovery,
    pysnmpUsmKeyType=__pysnmpUsmKeyType
)
