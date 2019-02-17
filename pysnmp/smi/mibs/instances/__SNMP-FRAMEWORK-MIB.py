#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This file instantiates some of the MIB managed objects for SNMP engine use
#

import time

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

MibScalarInstance, = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibScalarInstance'
)

(snmpEngineID,
 snmpEngineBoots,
 snmpEngineTime,
 snmpEngineMaxMessageSize) = mibBuilder.importSymbols(
    'SNMP-FRAMEWORK-MIB',
    'snmpEngineID',
    'snmpEngineBoots',
    'snmpEngineTime',
    'snmpEngineMaxMessageSize'
)

_snmpEngineID = MibScalarInstance(
    snmpEngineID.name, (0,),
    snmpEngineID.syntax
)
_snmpEngineBoots = MibScalarInstance(
    snmpEngineBoots.name, (0,),
    snmpEngineBoots.syntax.clone(1)
)
_snmpEngineTime = MibScalarInstance(
    snmpEngineTime.name, (0,),
    snmpEngineTime.syntax.clone(int(time.time()))
)
_snmpEngineMaxMessageSize = MibScalarInstance(
    snmpEngineMaxMessageSize.name, (0,),
    snmpEngineMaxMessageSize.syntax.clone(4096)
)

mibBuilder.exportSymbols(
    '__SNMP-FRAMEWORK-MIB',
    snmpEngineID=_snmpEngineID,
    snmpEngineBoots=_snmpEngineBoots,
    snmpEngineTime=_snmpEngineTime,
    snmpEngineMaxMessageSize=_snmpEngineMaxMessageSize
)
