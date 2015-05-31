#
# Asynchronous Command Generator
#
# Send SNMP GET requests using multiple independend SNMP engines 
# with the following options:
#
# * with SNMPv1, community 'public' and 
#   with SNMPv2c, community 'public' and
#   with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
# * over IPv4/UDP and 
#   over IPv6/UDP
# * to an Agent at demo.snmplabs.com:161 and
#   to an Agent at [::1]:161
# * for instances of SNMPv2-MIB::sysDescr.0 and
#   SNMPv2-MIB::sysLocation.0 MIB objects
#
# Within this script we have a single asynchronous TransportDispatcher
# and a single UDP-based transport serving two independent SNMP engines.
# We use a single instance of AsyncCommandGenerator with each of 
# SNMP Engines to comunicate GET command request to remote systems.
#
# When we receive a [response] message from remote system we use
# a custom message router to choose what of the two SNMP engines
# data packet should be handed over. The selection criteria we
# employ here is based on peer's UDP port number. Other selection
# criterias are also possible.
#
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.entity import engine
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher

# List of targets in the followin format:
# ( ( authData, transportTarget, varNames ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( cmdgen.CommunityData('public', mpModel=0),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( cmdgen.CommunityData('public'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 1161)),
      ( cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # 3-nd target (SNMPv3 over IPv4/UDP)
    ( cmdgen.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 2161)),
      ( cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) ) )
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
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
        return 1
    
    for oid, val in varBinds:
        if val is None:
            print(oid.prettyPrint())
        else:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))


# Instantiate the single transport dispatcher object
transportDispatcher = AsynsockDispatcher()

# Setup a custom data routing function to select snmpEngine by transportDomain
transportDispatcher.registerRoutingCbFun(
    lambda td,ta,d: ta[1] % 3 and 'A' or 'B'
)

snmpEngineA = engine.SnmpEngine()
snmpEngineA.registerTransportDispatcher(transportDispatcher, 'A')

snmpEngineB = engine.SnmpEngine()
snmpEngineB.registerTransportDispatcher(transportDispatcher, 'B')

cmdGen = cmdgen.AsyncCommandGenerator()

for authData, transportTarget, varBinds in targets:
    snmpEngine = transportTarget.getTransportInfo()[1][1] % 3 and \
            snmpEngineA or snmpEngineB
    cmdGen.getCmd(
        snmpEngine, authData, transportTarget, cmdgen.ContextData(), varBinds,
        (cbFun, (snmpEngine, authData, transportTarget))
    )

transportDispatcher.runDispatcher()
