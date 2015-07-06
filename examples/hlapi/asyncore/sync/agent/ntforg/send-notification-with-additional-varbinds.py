#
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv2c
# * with community name 'public'
# * over IPv4/UDP
# * send INFORM notification
# * with TRAP ID 'coldStart' specified as a MIB symbol
# * include managed object information specified as a MIB symbol
# * perform response OIDs and values resolution at MIB
#
from pysnmp.entity.rfc3413.oneliner.ntforg import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in \
        sendNotification(SnmpEngine(),
                         CommunityData('public'),
                         UdpTransportTarget(('localhost', 162)),
                         ContextData(),
                         'inform',
                         NotificationType(
                             ObjectIdentity('SNMPv2-MIB', 'coldStart')
                         ).addVarBinds(
                             ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0), 'my system') )
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
