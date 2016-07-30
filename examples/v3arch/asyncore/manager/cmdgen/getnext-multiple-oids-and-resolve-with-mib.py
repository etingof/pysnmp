"""
Walk Agent and resolve variables at MIB
+++++++++++++++++++++++++++++++++++++++

Send a series of SNMP GETNEXT requests with the following options:

* with SNMPv1, community 'public'
* over IPv4/UDP
* to an Agent at 104.236.166.95:161
* for two OIDs in tuple form
* stop on end-of-mib condition for both OIDs

This script performs similar to the following Net-SNMP command:

| $ snmpwalk -v1 -c public -ObentU 104.236.166.95 1.3.6.1.2.1.1 1.3.6.1.4.1.1

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.smi import compiler, view, rfc1902

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# Attach MIB compiler to SNMP Engine (MIB Builder)
# This call will fail if PySMI is not present on the system
compiler.addMibCompiler(snmpEngine.getMibBuilder())
# ... alternatively, this call will not complain on missing PySMI
# compiler.addMibCompiler(snmpEngine.getMibBuilder(), ifAvailable=True)

# Used for MIB objects resolution
mibViewController = view.MibViewController(snmpEngine.getMibBuilder())

# 
#
# SNMPv1/2c setup
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

#
# Setup transport endpoint and bind it with security settings yielding
# a target name
#

# UDP/IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-router',
    udp.domainName, ('104.236.166.95', 161),
    'my-creds'
)


# Error/response receiver
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):
    if errorIndication:
        print(errorIndication)
        return
    # SNMPv1 response may contain noSuchName error *and* SNMPv2c exception,
    # so we ignore noSuchName error here
    if errorStatus and errorStatus != 2:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBindTable[-1][int(errorIndex) - 1][0] or '?'))
        return  # stop on error
    for varBindRow in varBindTable:
        for varBind in varBindRow:
            print(rfc1902.ObjectType(rfc1902.ObjectIdentity(varBind[0]),
                                     varBind[1]).resolveWithMib(mibViewController).prettyPrint())
    return 1  # signal dispatcher to continue


# Prepare initial request to be sent
cmdgen.NextCommandGenerator().sendVarBinds(
    snmpEngine,
    'my-router',
    None, '',  # contextEngineId, contextName
    [rfc1902.ObjectType(rfc1902.ObjectIdentity('iso.org.dod')).resolveWithMib(mibViewController),
     rfc1902.ObjectType(rfc1902.ObjectIdentity('IF-MIB', 'ifMIB')).resolveWithMib(mibViewController)],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
