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
from pysnmp.entity.rfc3413.oneliner import ntforg

ntfOrg = ntforg.NotificationOriginator()

errorIndication = ntfOrg.sendNotification(
    ntforg.CommunityData('public'),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'trap',
    ntforg.NotificationType(ntforg.ObjectIdentity('SNMPv2-MIB', 'coldStart'))
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
