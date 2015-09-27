"""
Sending additional var-binds
++++++++++++++++++++++++++++

Send SNMP notification using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send INFORM notification
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as a MIB symbol

Functionally similar to:

| $ snmpinform -v2c -c public 
|              demo.snmplabs.com \
|              12345 \
|              1.3.6.1.6.3.1.1.5.1 \
|              1.3.6.1.2.1.1.1.0 s 'my system'

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(SnmpEngine(),
                     CommunityData('public'),
                     UdpTransportTarget(('localhost', 162)),
                     ContextData(),
                     'inform',
                     NotificationType(
                         ObjectIdentity('SNMPv2-MIB', 'coldStart')
                     ).addVarBinds(
                         ObjectType(ObjectIdentity('SNMPv2-MIB','sysName',0),
                                                   'my system')
                     ))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
        )
    )
else:
    for varBind in varBinds:
        print(' = '.join([ x.prettyPrint() for x in varBind ]))
