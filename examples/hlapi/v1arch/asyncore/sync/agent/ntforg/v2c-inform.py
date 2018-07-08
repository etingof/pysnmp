"""
SNMPv2c INFORM
++++++++++++++

Send SNMP INFORM notification using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send INFORM notification
* with TRAP ID 'warmStart' specified as a string OID
* include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'

Functionally similar to:

| $ snmpinform -v2c -c public demo.snmplabs.com 12345 1.3.6.1.4.1.20408.4.1.1.2 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.hlapi.v1arch import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(
        SnmpDispatcher(),
        CommunityData('public'),
        UdpTransportTarget(('demo.snmplabs.com', 162)),
        'inform',
        # SNMPv2-MIB::sysUpTime.0 = 12345
        ('1.3.6.1.2.1.1.3.0', TimeTicks(12345)),
        # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::warmStart
        ('1.3.6.1.6.3.1.1.4.1.0', ObjectIdentifier('1.3.6.1.6.3.1.1.5.2')),
        # SNMPv2-MIB::sysName.0
        ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
    )
)

if errorIndication:
    print(errorIndication)

elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
