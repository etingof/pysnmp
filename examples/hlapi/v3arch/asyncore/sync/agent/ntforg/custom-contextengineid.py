"""
INFORM with custom ContextEngineId
++++++++++++++++++++++++++++++++++

Send SNMP notification using the following options:

* SNMPv3
* with user 'usr-md5-none', MD5 auth, no priv
* send INFORM notification
* in behalf of contextEngineId 0x8000000004030201, contextName ''
* over IPv4/UDP
* with TRAP ID 'warmStart' specified as a string OID

Sending SNMPv3 Notification in behalf of non-default ContextEngineId
requires having a collection of Managed Objects registered under
the ContextEngineId being used.

Functionally similar to:

| $ snmpinform -v3 -l authNoPriv -u usr-md5-none -A authkey1 -E 0x8000000004030201 demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(SnmpEngine(),
                     UsmUserData('usr-md5-none', 'authkey1'),
                     UdpTransportTarget(('demo.snmplabs.com', 162)),
                     ContextData(OctetString(hexValue='8000000004030201')),
                     'inform',
                     NotificationType(
                         ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
                     ).loadMibs('SNMPv2-MIB')
    )
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
