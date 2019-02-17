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

(snmpUnknownSecurityModels,
 snmpInvalidMsgs,
 snmpUnknownPDUHandlers) = mibBuilder.importSymbols(
    'SNMP-MPD-MIB',
    'snmpUnknownSecurityModels',
    'snmpInvalidMsgs',
    'snmpUnknownPDUHandlers',
)

_snmpUnknownSecurityModels = MibScalarInstance(
    snmpUnknownSecurityModels.name, (0,),
    snmpUnknownSecurityModels.syntax.clone(0)
)
_snmpInvalidMsgs = MibScalarInstance(
    snmpInvalidMsgs.name, (0,),
    snmpInvalidMsgs.syntax.clone(0)
)
_snmpUnknownPDUHandlers = MibScalarInstance(
    snmpUnknownPDUHandlers.name, (0,),
    snmpUnknownPDUHandlers.syntax.clone(0)
)

mibBuilder.exportSymbols(
    '__SNMP-MPD-MIB',
    snmpUnknownSecurityModels=_snmpUnknownSecurityModels,
    snmpInvalidMsgs=_snmpInvalidMsgs,
    snmpUnknownPDUHandlers=_snmpUnknownPDUHandlers
)
