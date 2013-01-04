#
# Notification Originator
#
# Send multiple SNMP notifications using the following options:
#
# * SNMPv1 and SNMPv2c
# * with community name 'public'
# * over IPv4/UDP
# * send TRAP notification
# * to multiple Managers
# * with TRAP ID 'coldStart' specified as a MIB symbol
# * include managed object information specified as var-bind objects pair
#
from pysnmp.entity.rfc3413.oneliner import ntforg
from pysnmp.proto import rfc1902

# List of targets in the followin format:
# ( ( authData, transportTarget ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( ntforg.CommunityData('public', mpModel=0),
      ntforg.UdpTransportTarget(('localhost', 162)) ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( ntforg.CommunityData('public'),
      ntforg.UdpTransportTarget(('localhost', 162)) )
)

ntfOrg = ntforg.AsynNotificationOriginator()

for authData, transportTarget in targets:
    ntfOrg.sendNotification(
        authData,
        transportTarget,
        'trap',
        ntforg.MibVariable('SNMPv2-MIB', 'coldStart'),
        ( ( rfc1902.ObjectName('1.3.6.1.2.1.1.1.0'),
            rfc1902.OctetString('my name') ), )
    )

ntfOrg.snmpEngine.transportDispatcher.runDispatcher()
