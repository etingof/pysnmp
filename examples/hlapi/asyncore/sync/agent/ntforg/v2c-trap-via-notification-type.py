#
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv2c
# * with community name 'public'
# * over IPv4/UDP
# * send TRAP notification
# * with TRAP ID 'coldStart' specified as a MIB symbol
# * include managed object information specified as a MIB symbol
#
from pysnmp.entity.rfc3413.oneliner.ntforg import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in \
        sendNotification(SnmpEngine(),
                         CommunityData('public'),
                         UdpTransportTarget(('localhost', 162)),
                         ContextData(),
                         'trap',
                         NotificationType(
                             ObjectIdentity('SNMPv2-MIB', 'coldStart')
                         )):
    if errorIndication:
        print(errorIndication)
