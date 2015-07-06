#
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv1
# * with community name 'public'
# * over IPv4/UDP
# * send TRAP notification
# * with Generic Trap #1 (warmStart) and Specific Trap 0
# * with default Uptime
# * with default Agent Address
# * with Enterprise OID 1.3.6.1.4.1.20408.4.1.1.2
# * include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'
#
from pysnmp.entity.rfc3413.oneliner.ntforg import *
from pysnmp.proto import rfc1902

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in \
        sendNotification(SnmpEngine(),
                         CommunityData('public', mpModel=0),
                         UdpTransportTarget(('localhost', 162)),
                         ContextData(),
                         'trap',
                         NotificationType(
                             ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
                         ).addVarBinds(
                             ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
                             ('1.3.6.1.2.1.1.1.0', rfc1902.OctetString('my system'))
                         )):
    if errorIndication:
        print(errorIndication)
