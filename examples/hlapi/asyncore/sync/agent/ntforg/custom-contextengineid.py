#
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv3
# * with user 'usr-md5-none', MD5 auth, no priv
# * send INFORM notification
# * in behalf of contextEngineId 0x8000000004030201, contextName ''
# * over IPv4/UDP
# * with TRAP ID 'warmStart' specified as a string OID
#
# Sending SNMPv3 Notification in behalf of non-default ContextEngineId
# requires having a collection of Managed Objects registered under
# the ContextEngineId being used.
#
from pysnmp.entity.rfc3413.oneliner.ntforg import *
from pysnmp.proto import rfc1902

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in \
        sendNotification(SnmpEngine(),
                         UsmUserData('usr-md5-none', 'authkey1'),
                         UdpTransportTarget(('localhost', 162)),
                         ContextData(
                             rfc1902.OctetString(hexValue='8000000004030201')
                         ),
                         'inform',
                         NotificationType(
                             ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
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
