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

(snmpTargetSpinLock,
 snmpUnavailableContexts,
 snmpUnknownContexts) = mibBuilder.importSymbols(
    'SNMP-TARGET-MIB',
    'snmpTargetSpinLock',
    'snmpUnavailableContexts',
    'snmpUnknownContexts'
)

_snmpTargetSpinLock = MibScalarInstance(
    snmpTargetSpinLock.name, (0,),
    snmpTargetSpinLock.syntax.clone(0)
)
_snmpUnavailableContexts = MibScalarInstance(
    snmpUnavailableContexts.name, (0,),
    snmpUnavailableContexts.syntax.clone(0)
)
_snmpUnknownContexts = MibScalarInstance(
    snmpUnknownContexts.name, (0,),
    snmpUnknownContexts.syntax.clone(0)
)

mibBuilder.exportSymbols(
    '__SNMP-TARGET-MIB',
    snmpTargetSpinLock=_snmpTargetSpinLock,
    snmpUnavailableContexts=_snmpUnavailableContexts,
    snmpUnknownContexts=_snmpUnknownContexts
)
