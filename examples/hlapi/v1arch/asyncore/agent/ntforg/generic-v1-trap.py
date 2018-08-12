"""
Generic SNMPv1 TRAP
+++++++++++++++++++

Send SNMPv1 TRAP using the following options:

* SNMPv1
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with Uptime 12345
* with Generic Trap #1 (warmStart) and Specific Trap 0
* with Agent Address 127.0.0.1
* with Enterprise OID 1.3.6.1.4.1.20408.4.1.1.2
* include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'

Functionally similar to:

| $ snmptrap -v1 -c public demo.snmplabs.com 1.3.6.1.4.1.20408.4.1.1.2 0.0.0.0 1 0 0 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.hlapi.v1arch.asyncore import *


def cbFun(errorIndication, errorStatus, errorIndex, varBinds, **context):
    if errorIndication:
        print(errorIndication)


snmpDispatcher = SnmpDispatcher()

sendNotification(
    snmpDispatcher,
    CommunityData('public', mpModel=0),
    UdpTransportTarget(('demo.snmplabs.com', 162)),
    'trap',
    # SNMPv2-MIB::sysUpTime.0 = 12345
    ('1.3.6.1.2.1.1.3.0', TimeTicks(12345)),
    # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::warmStart
    ('1.3.6.1.6.3.1.1.4.1.0', ObjectIdentifier('1.3.6.1.6.3.1.1.5.2')),
    # SNMP-COMMUNITY-MIB::snmpTrapAddress.0 = 127.0.0.1
    ('1.3.6.1.6.3.18.1.3.0', IpAddress('127.0.0.1')),
    # SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 = public
    ('1.3.6.1.6.3.18.1.4.0', OctetString('public')),
    # SNMP-COMMUNITY-MIB::snmpTrapEnterprise.0 = 1.3.6.1.4.1.20408.4.1.1.2
    ('1.3.6.1.6.3.1.1.4.3.0', ObjectIdentifier('1.3.6.1.4.1.20408.4.1.1.2')),
    # SNMPv2-MIB::sysName.0
    ('1.3.6.1.2.1.1.1.0', OctetString('my system')),
    cbFun=cbFun
)

snmpDispatcher.transportDispatcher.runDispatcher()
