#
# Notification Originator
#
# Send multiple SNMP notifications using the following options:
#
# * SNMPv2c and SNMPv3
# * with community name 'public' or USM username usr-md5-des
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
    # 1-st target (SNMPv2c over IPv4/UDP)
    ( ntforg.CommunityData('public'),
      ntforg.UdpTransportTarget(('localhost', 162)) ),
    # 2-nd target (SNMPv3 over IPv4/UDP)
    ( ntforg.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      ntforg.UdpTransportTarget(('localhost', 162)) )
)

ntfOrg = ntforg.AsynNotificationOriginator()

def cbFun(sendRequestHandle, errorIndication, 
          errorStatus, errorIndex, varBinds, cbctx):
    if errorIndication:
        print('Notification %s not sent: %s' % (sendRequestHandle, errorIndication))
    elif errorStatus:
        print('Notification Receiver returned error for %s: %s @%s' %
              (sendRequestHandle, errorStatus, errorIndex))
    else:
        print('Notification %s delivered:' % sendRequestHandle)
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

for authData, transportTarget in targets:
    sendPduHandle = ntfOrg.sendNotification(
        authData,
        transportTarget,
        'inform',
        ntforg.MibVariable('SNMPv2-MIB', 'coldStart'),
        ( ( rfc1902.ObjectName('1.3.6.1.2.1.1.1.0'),
            rfc1902.OctetString('my name') ), ),
        cbInfo=(cbFun, None)
    )

ntfOrg.snmpEngine.transportDispatcher.runDispatcher()
