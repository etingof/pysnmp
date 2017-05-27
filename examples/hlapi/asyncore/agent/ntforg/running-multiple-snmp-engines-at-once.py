"""
Multiple SNMP Engines
+++++++++++++++++++++

Send SNMP notifications in behalf of multiple independend SNMP engines 
using the following options:

* with a single transport dispatcher and two independent SNMP engines
* SNMPv2c and SNMPv3
* with community name 'public' or USM username usr-md5-des
* over IPv4/UDP
* send IMFORM notification
* to multiple Managers
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as var-bind objects pair

Within this script we have a single asynchronous TransportDispatcher
and a single UDP-based transport serving two independent SNMP engines.
We use a single instance of AsyncNotificationOriginator with each of 
SNMP Engines to communicate INFORM notification to remote systems.

When we receive a [response] message from remote system we use
a custom message router to choose what of the two SNMP engines
data packet should be handed over. The selection criteria we
employ here is based on peer's UDP port number. Other selection
criterias are also possible.

| $ snmpinform -v2c -c public demo.snmplabs.com:1162 123 1.3.6.1.6.3.1.1.5.1
| $ snmpinform -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 demo.snmplabs.com 123 1.3.6.1.6.3.1.1.5.1

"""#
from pysnmp.hlapi.asyncore import *
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher

# List of targets in the following format:
# ( ( authData, transportTarget ), ... )
targets = (
    # 1-st target (SNMPv2c over IPv4/UDP)
    (CommunityData('public'),
     UdpTransportTarget(('demo.snmplabs.com', 1162)),
     ContextData()),
    # 2-nd target (SNMPv3 over IPv4/UDP)
    (UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
     UdpTransportTarget(('demo.snmplabs.com', 162)),
     ContextData()),
)


# noinspection PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    snmpEngine = cbCtx
    if errorIndication:
        print('Notification %s for %s not sent: %s' % (sendRequestHandle, snmpEngine.snmpEngineID.prettyPrint(), errorIndication))
    elif errorStatus:
        print('Notification Receiver returned error for request %s, SNMP Engine %s: %s @%s' % (sendRequestHandle, snmpEngine.snmpEngineID.prettyPrint(), errorStatus, errorIndex))
    else:
        print('Notification %s for SNMP Engine %s delivered:' % (sendRequestHandle, snmpEngine.snmpEngineID.prettyPrint()))
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


# Instantiate the single transport dispatcher object
transportDispatcher = AsyncoreDispatcher()

# Setup a custom data routing function to select snmpEngine by transportDomain
transportDispatcher.registerRoutingCbFun(
    lambda td, ta, d: ta[1] % 3 and 'A' or 'B'
)

snmpEngineA = SnmpEngine()
snmpEngineA.registerTransportDispatcher(transportDispatcher, 'A')

snmpEngineB = SnmpEngine()
snmpEngineB.registerTransportDispatcher(transportDispatcher, 'B')

for authData, transportTarget, contextData in targets:
    snmpEngine = (transportTarget.getTransportInfo()[1][1] % 3 and
                  snmpEngineA or snmpEngineB)
    sendPduHandle = sendNotification(
        snmpEngine,
        authData,
        transportTarget,
        contextData,
        'inform',  # NotifyType
        NotificationType(
            ObjectIdentity('SNMPv2-MIB', 'coldStart')
        ).addVarBinds(('1.3.6.1.2.1.1.1.0', 'my name')),
        cbFun=cbFun, cbCtx=snmpEngine
    )

transportDispatcher.runDispatcher()
