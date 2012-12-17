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
from pysnmp.entity.rfc3413.oneliner import ntforg
from pysnmp.proto import rfc1902

ntfOrg = ntforg.NotificationOriginator()

errorIndication = ntfOrg.sendNotification(
    ntforg.CommunityData('public', mpModel=0),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'trap',
    '1.3.6.1.6.3.1.1.5.2',
    ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
    ('1.3.6.1.2.1.1.1.0', rfc1902.OctetString('my system'))
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
