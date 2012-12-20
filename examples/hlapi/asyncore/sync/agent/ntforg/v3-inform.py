##
# Notification Originator
#
# Send SNMP notification using the following options:
#
# * SNMPv3
# * with user 'usr-md5-des', auth: MD5, priv DES
# * over IPv4/UDP
# * send INFORM notification
# * with TRAP ID 'warmStart' specified as a string OID
# * include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'
#
from pysnmp.entity.rfc3413.oneliner import ntforg
from pysnmp.proto import rfc1902

ntfOrg = ntforg.NotificationOriginator()

errorIndication, errorStatus, errorIndex, varBinds = ntfOrg.sendNotification(
    ntforg.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
    ntforg.UdpTransportTarget(('localhost', 162)),
    'inform',
    '1.3.6.1.6.3.1.1.5.2',
    ('1.3.6.1.2.1.1.5.0', rfc1902.OctetString('system name'))
)

if errorIndication:
    print('Notification not sent: %s' % errorIndication)
elif errorStatus:
    print('Notification Receiver returned error: %s @%s' %
          (errorStatus, errorIndex))
else:
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
