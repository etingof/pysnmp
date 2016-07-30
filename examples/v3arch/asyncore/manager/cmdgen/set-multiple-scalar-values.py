"""
SET string and integer scalars
++++++++++++++++++++++++++++++

Send SNMP SET request with the following options:

* with SNMPv1 with community name 'private'
* over IPv4/UDP
* to an Agent at 104.236.166.95:161
* for OIDs in tuple form and an integer and string-typed values

This script performs similar to the following Net-SNMP command:

| $ snmpset -v1 -c private -ObentU 104.236.166.95:161 1.3.6.1.2.1.1.9.1.3.1 s 'my value'  1.3.6.1.2.1.1.9.1.4.1 t 123 

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import rfc1902

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv1 setup
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'private')

# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 0)

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
          errorStatus, errorIndex, varBinds, cbCtx):
    if errorIndication:
        print(errorIndication)
    # SNMPv1 response may contain noSuchName error *and* SNMPv2c exception,
    # so we ignore noSuchName error here
    elif errorStatus and errorStatus != 2:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for oid, val in varBinds:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))


# Prepare and send a request message
cmdgen.SetCommandGenerator().sendVarBinds(
    snmpEngine,
    'my-router',
    None, '',  # contextEngineId, contextName
    [((1, 3, 6, 1, 2, 1, 1, 9, 1, 3, 1), rfc1902.OctetString('my value')),
     ((1, 3, 6, 1, 2, 1, 1, 9, 1, 4, 1), rfc1902.TimeTicks(123))],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
