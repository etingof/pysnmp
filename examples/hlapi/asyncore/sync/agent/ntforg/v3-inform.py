"""
INFORM, auth: MD5 privacy: DES
++++++++++++++++++++++++++++++

Send SNMP INFORM notification using the following options:

* SNMPv3
* with user 'usr-md5-des', auth: MD5, priv DES
* over IPv4/UDP
* send INFORM notification
* with TRAP ID 'warmStart' specified as a string OID
* include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'

Functionally similar to:

| $ snmpinform -v3 -l authPriv -u usr-sha-aes -A authkey1 -X privkey1 \
|              demo.snmplabs.com \
|              12345 \
|              1.3.6.1.4.1.20408.4.1.1.2 \
|              '1.3.6.1.2.1.1.1.0' s 'my system'

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(SnmpEngine(),
                     UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                     UdpTransportTarget(('localhost', 162)),
                     ContextData(),
                     'inform',
                     NotificationType(
                         ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
                     ).addVarBinds(
                         ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'),
                                    'system name')
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
