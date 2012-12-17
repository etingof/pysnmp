#
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv3
# * with user 'usr-md5-none', MD5 auth, no priv
# * send INFORM notification
# * in behalf of contextEngineId = SnmpEngineId, contextName 'my-context'
# * over IPv4/UDP
# * with TRAP ID 'warmStart' specified as a string OID
#
# Sending SNMPv3 Notification in behalf of non-default ContextName
# requires having a collection of Managed Objects registered under
# the ContextName being used.
#
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import context
from pysnmp.entity.rfc3413.oneliner import ntforg

snmpEngine = engine.SnmpEngine()
snmpContext = context.SnmpContext(snmpEngine)

# register default collection of Managed Objects under new contextName
snmpContext.registerContextName('my-context', snmpContext.getMibInstrum())

ntfOrg = ntforg.NotificationOriginator(snmpEngine, snmpContext)

errorIndication, errorStatus, errorIndex, varBinds = ntfOrg.sendNotification(
    ntforg.UsmUserData('usr-md5-none', 'authkey1'),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'inform',
    '1.3.6.1.6.3.1.1.5.2',
    contextName='my-context'
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
elif errorStatus:
    print('Notification Receiver returned error: %s @%s' % (errorStatus, errorIndex))
else:
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
