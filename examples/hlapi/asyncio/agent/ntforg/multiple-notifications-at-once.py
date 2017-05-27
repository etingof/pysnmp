"""
Multiple concurrent notifications
+++++++++++++++++++++++++++++++++

Send multiple SNMP notifications at once using the following options:

* SNMPv2c and SNMPv3
* with community name 'public'
* over IPv4/UDP
* send INFORM notification
* to multiple Managers
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as var-bind objects pair

Here we tag each SNMP-COMMUNITY-MIB::snmpCommunityTable row
with the same tag as SNMP-TARGET-MIB::snmpTargetAddrTable row
what leads to excessive tables information.

Functionally similar to:

| $ snmptrap -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2
| $ snmpinform -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2
| $ snmptrap -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2

"""#
import asyncio
from pysnmp.hlapi.asyncio import *


@asyncio.coroutine
def sendone(snmpEngine, hostname, notifyType):
    (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) = yield from sendNotification(
        snmpEngine,
        CommunityData('public', tag=hostname),
        UdpTransportTarget((hostname, 162), tagList=hostname),
        ContextData(),
        notifyType,
        NotificationType(
            ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
        ).addVarBinds(
            ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
            ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
        )
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s: at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


snmpEngine = SnmpEngine()

loop = asyncio.get_event_loop()
loop.run_until_complete(
    asyncio.wait([sendone(snmpEngine, 'demo.snmplabs.com', 'trap'),
                  sendone(snmpEngine, 'demo.snmplabs.com', 'inform')])
)
