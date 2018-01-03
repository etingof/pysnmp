#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
MibScalarInstance, = mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalarInstance')

(snmpUnknownSecurityModels,
 snmpInvalidMsgs,
 snmpUnknownPDUHandlers) = mibBuilder.importSymbols(
    'SNMP-MPD-MIB',
    'snmpUnknownSecurityModels',
    'snmpInvalidMsgs',
    'snmpUnknownPDUHandlers',
)

__snmpUnknownSecurityModels = MibScalarInstance(snmpUnknownSecurityModels.name, (0,),
                                                snmpUnknownSecurityModels.syntax.clone(0))
__snmpInvalidMsgs = MibScalarInstance(snmpInvalidMsgs.name, (0,), snmpInvalidMsgs.syntax.clone(0))
__snmpUnknownPDUHandlers = MibScalarInstance(snmpUnknownPDUHandlers.name, (0,), snmpUnknownPDUHandlers.syntax.clone(0))

mibBuilder.exportSymbols(
    '__SNMP-MPD-MIB',
    snmpUnknownSecurityModels=__snmpUnknownSecurityModels,
    snmpInvalidMsgs=__snmpInvalidMsgs,
    snmpUnknownPDUHandlers=__snmpUnknownPDUHandlers
)
