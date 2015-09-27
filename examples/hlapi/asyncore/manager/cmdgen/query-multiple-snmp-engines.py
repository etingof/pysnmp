"""
Multiple SNMP engines
+++++++++++++++++++++

Send multiple SNMP GET requests to multiple peers using multiple 
independend SNMP engines. Deal with peers asynchronously. SNMP options
are:

* with SNMPv1, community 'public' and 
  with SNMPv2c, community 'public' and
  with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
* over IPv4/UDP and 
  over IPv6/UDP
* to an Agent at demo.snmplabs.com:161 and
  to an Agent at [::1]:161
* for instances of SNMPv2-MIB::sysDescr.0 and
  SNMPv2-MIB::sysLocation.0 MIB objects

Within this script we have a single asynchronous TransportDispatcher
and a single UDP-based transport serving two independent SNMP engines.
We use a single instance of AsyncCommandGenerator with each of 
SNMP Engines to comunicate GET command request to remote systems.

When we receive a [response] message from remote system we use
a custom message router to choose what of the two SNMP engines
data packet should be handed over. The selection criteria we
employ here is based on peer's UDP port number. Other selection
criterias are also possible.

"""#
from pysnmp.hlapi.asyncore import *
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher

# List of targets in the following format:
# ( ( authData, transportTarget, varNames ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( CommunityData('public', mpModel=0),
      UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( CommunityData('public'),
      UdpTransportTarget(('demo.snmplabs.com', 1161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # 3-nd target (SNMPv3 over IPv4/UDP)
    ( UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      UdpTransportTarget(('demo.snmplabs.com', 2161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) )
    # N-th target
    # ...
)

# Wait for responses or errors
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    (snmpEngine, authData, transportTarget) = cbCtx
    print('snmpEngine %s: %s via %s' % 
        (snmpEngine.snmpEngineID.prettyPrint(), authData, transportTarget)
    )
    if errorIndication:
        print(errorIndication)
        return 1
    elif errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
        return 1
    else:
        for varBind in varBinds:
            print(' = '.join([ x.prettyPrint() for x in varBind ]))

# Instantiate the single transport dispatcher object
transportDispatcher = AsyncoreDispatcher()

# Setup a custom data routing function to select snmpEngine by transportDomain
transportDispatcher.registerRoutingCbFun(
    lambda td,ta,d: ta[1] % 3 and 'A' or 'B'
)

snmpEngineA = SnmpEngine()
snmpEngineA.registerTransportDispatcher(transportDispatcher, 'A')

snmpEngineB = SnmpEngine()
snmpEngineB.registerTransportDispatcher(transportDispatcher, 'B')

for authData, transportTarget, varBinds in targets:
    snmpEngine = transportTarget.getTransportInfo()[1][1] % 3 and \
            snmpEngineA or snmpEngineB
    getCmd(snmpEngine, authData, transportTarget, ContextData(), *varBinds,
           **dict(cbFun=cbFun, cbCtx=(snmpEngine, authData, transportTarget)))

transportDispatcher.runDispatcher()
