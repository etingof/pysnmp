"""
Multiple concurrent queries
+++++++++++++++++++++++++++

Send a bunch of different SNMP Notifications to different peers all at once,
wait for responses asynchronously:

* SNMPv1 and SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* to multiple Managers
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as var-bind objects pair

| $ snmptrap -v1 -c public demo.snmplabs.com 1.3.6.1.4.1.20408.4.1.1.2 demo.snmplabs.com 6 432 12345 1.3.6.1.2.1.1.1.0 s "my system"
| $ snmptrap -v2c -c public demo.snmplabs.com 123 1.3.6.1.6.3.1.1.5.1

"""#
from pysnmp.hlapi.asyncore import *

# List of targets in the followin format:
# ( ( authData, transportTarget ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    (CommunityData('public', mpModel=0),
     UdpTransportTarget(('demo.snmplabs.com', 162)),
     ContextData()),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    (CommunityData('public'),
     UdpTransportTarget(('demo.snmplabs.com', 162)),
     ContextData()),
)

snmpEngine = SnmpEngine()

for authData, transportTarget, contextData in targets:
    sendNotification(
        snmpEngine,
        authData,
        transportTarget,
        contextData,
        'trap',  # NotifyType
        NotificationType(
            ObjectIdentity('SNMPv2-MIB', 'coldStart')
        ).addVarBinds(
            (ObjectIdentifier('1.3.6.1.2.1.1.1.0'),
             OctetString('my name'))
        )
    )

snmpEngine.transportDispatcher.runDispatcher()
