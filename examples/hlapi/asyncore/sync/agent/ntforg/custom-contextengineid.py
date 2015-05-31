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
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import context
from pysnmp.entity.rfc3413.oneliner import ntforg
from pysnmp.proto import rfc1902

snmpEngine = engine.SnmpEngine()

ntfOrg = ntforg.NotificationOriginator(snmpEngine)

errorIndication, errorStatus, errorIndex, varBinds = ntfOrg.sendNotification(
    ntforg.UsmUserData('usr-md5-none', 'authkey1'),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'inform',
    ntforg.NotificationType(ntforg.ObjectIdentity('1.3.6.1.6.3.1.1.5.2')),
    contextEngineId=rfc1902.OctetString(hexValue='8000000004030201')
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
elif errorStatus:
    print('Notification Receiver returned error: %s @%s' %
          (errorStatus, errorIndex))
else:
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
