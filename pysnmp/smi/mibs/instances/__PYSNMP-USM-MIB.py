( MibScalarInstance, ) = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibScalarInstance'
    )

( pysnmpUsmDiscoverable,
  pysnmpUsmDiscovery ) = mibBuilder.importSymbols(
    'PYSNMP-USM-MIB',
    'pysnmpUsmDiscoverable',
    'pysnmpUsmDiscovery'
    )

__pysnmpUsmDiscoverable = MibScalarInstance(pysnmpUsmDiscoverable.name, (0,), pysnmpUsmDiscoverable.syntax)
__pysnmpUsmDiscovery = MibScalarInstance(pysnmpUsmDiscovery.name, (0,), pysnmpUsmDiscovery.syntax)

mibBuilder.exportSymbols(
    "__PYSNMP-USM-MIB",
    pysnmpUsmDiscoverable = __pysnmpUsmDiscoverable,
    pysnmpUsmDiscovery = __pysnmpUsmDiscovery
    )
