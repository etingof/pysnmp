"""
SNMPv2c TRAP via Twisted inline callbacks
+++++++++++++++++++++++++++++++++++++++++

Send SNMPv2c TRAP through unified SNMPv3 message processing framework
using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with Generic Trap #1 (warmStart) and Specific Trap 0
* include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'

Functionally similar to:

| $ snmptrap -v2c -c public demo.snmplabs.com 12345 1.3.6.1.6.3.1.1.5.2 1.3.6.1.2.1.1.1.0 s "Hello from Twisted"

"""#
from twisted.internet.task import react, defer
from pysnmp.hlapi.twisted import *


@defer.inlineCallbacks
def sendtrap(reactor, snmpEngine, hostname):

    yield sendNotification(
        snmpEngine,
        CommunityData('public', mpModel=0),
        UdpTransportTarget((hostname, 162)),
        ContextData(),
        'trap',
        NotificationType(
            ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
        ).addVarBinds(
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), OctetString('Hello from Twisted'))
        )
    )

# Preserve SnmpEngine instance across [potentially] multiple calls to safe on initialization
snmpEngine = SnmpEngine()

react(sendtrap, [snmpEngine, 'demo.snmplabs.com'])

