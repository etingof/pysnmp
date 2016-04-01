"""
Serve SNMP Community names defined by regexp
++++++++++++++++++++++++++++++++++++++++++++

Receive SNMP TRAP/INFORM messages with the following options:

* SNMPv1/SNMPv2c
* with any SNMP community matching regexp '.*love.*'
* over IPv4/UDP, listening at 127.0.0.1:162
* print received data on stdout

Either of the following Net-SNMP commands will send notifications to this
receiver:

| $ snmptrap -v1 -c rollover 127.0.0.1 1.3.6.1.4.1.20408.4.1.1.2 127.0.0.1 1 1 123 1.3.6.1.2.1.1.1.0 s test
| $ snmpinform -v2c -c glove 127.0.0.1 123 1.3.6.1.6.3.1.1.5.1

The Notification Receiver below taps on v1/v2c SNMP security module
to deliver certains values, normally internal to SNMP Engine, up to
the context of user application.

This script examines the value of CommunityName, as it came from peer SNMP
Engine, and may modify it to match the only locally configured CommunityName
'public'. This effectively makes NotificationReceiver accepting messages with
CommunityName's, not explicitly configured to local SNMP Engine.

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
import re

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()


# Register a callback to be invoked at specified execution point of
# SNMP Engine and passed local variables at execution point's local scope.
# If at this execution point passed variables are modified, their new
# values will be propagated back and used by SNMP Engine for securityName
# selection.
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def requestObserver(snmpEngine, execpoint, variables, cbCtx):
    if re.match('.*love.*', str(variables['communityName'])):
        print('Rewriting communityName \'%s\' from %s into \'public\'' % (variables['communityName'], ':'.join([str(x) for x in variables['transportInformation'][1]])))
        variables['communityName'] = variables['communityName'].clone('public')


snmpEngine.observer.registerObserver(
    requestObserver,
    'rfc2576.processIncomingMsg:writable'
)

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 162))
)

# SNMPv1/2c setup

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')


# Callback function for receiving notifications
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    print('Notification from ContextEngineId "%s", ContextName "%s"' % (contextEngineId.prettyPrint(),
                                                                        contextName.prettyPrint()))
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmpEngine, cbFun)

snmpEngine.transportDispatcher.jobStarted(1)  # this job would never finish

# Run I/O dispatcher which would receive queries and send confirmations
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
