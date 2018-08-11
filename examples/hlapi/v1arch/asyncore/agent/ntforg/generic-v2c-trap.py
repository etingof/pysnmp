"""
Generic SNMPv2c TRAP
++++++++++++++++++++

Send SNMPv1 TRAP using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with Uptime 12345
* with Generic Trap #1 (warmStart) and Specific Trap 0
* include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'

Functionally similar to:

| $ snmptrap -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.hlapi.v1arch.asyncore import *


def cbFun(errorIndication, errorStatus, errorIndex, varBinds, **context):
    if errorIndication:
        print(errorIndication)


snmpDispatcher = SnmpDispatcher()

sendNotification(
    snmpDispatcher,
    CommunityData('public'),
    UdpTransportTarget(('demo.snmplabs.com', 162)),
    'trap',
    # SNMPv2-MIB::sysUpTime.0 = 12345
    ('1.3.6.1.2.1.1.3.0', TimeTicks(12345)),
    # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::warmStart
    ('1.3.6.1.6.3.1.1.4.1.0', ObjectIdentifier('1.3.6.1.6.3.1.1.5.2')),
    # SNMPv2-MIB::sysName.0
    ('1.3.6.1.2.1.1.1.0', OctetString('my system')),
    cbFun=cbFun
)

snmpDispatcher.transportDispatcher.runDispatcher()
