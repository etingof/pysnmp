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
from pysnmp.entity.rfc3413.oneliner import ntforg

ntfOrg = ntforg.NotificationOriginator()

errorIndication, errorStatus, errorIndex, varBinds = ntfOrg.sendNotification(
    ntforg.CommunityData('public'),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'inform',
    ntforg.MibVariable('SNMPv2-MIB', 'coldStart'),
    ( ntforg.MibVariable('SNMPv2-MIB', 'sysName', 0), 'my system' ),
    lookupNames=True, lookupValues=True
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
elif errorStatus:
    print('Notification Receiver returned error: %s @%s' % 
          (errorStatus, errorIndex))
else:
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


