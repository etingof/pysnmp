##
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv3
# * with user 'usr-md5-des', auth: MD5, priv DES
# * over IPv4/UDP
# * send INFORM notification
# * with TRAP ID 'warmStart' specified as a string OID
# * include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'
#
from pysnmp.entity.rfc3413.oneliner.ntforg import *
from pysnmp.proto import rfc1902

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in \
        sendNotification(SnmpEngine(),
                         UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                         UdpTransportTarget(('localhost', 162)),
                         ContextData(),
                         'inform',
                         NotificationType(
                             ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
                         ).addVarBinds(
                             ( ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'),
                                          rfc1902.OctetString('system name')) )
                         ),
                         lookupNames=True, lookupValues=True):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))

