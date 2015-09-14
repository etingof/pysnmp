"""
SNMPv2c, custom timeout
+++++++++++++++++++++++

Send a SNMP GET request:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at 195.218.195.228:161
* wait 3 seconds for response, retry 5 times (plus one initial attempt)
* for an OID in tuple form

This script performs similar to the following Net-SNMP command:

| $ snmpget -v2c -c public -ObentU -r 5 -t 1 195.218.195.228 1.3.6.1.2.1.1.1.0

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv2c setup
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
    udp.domainName, ('195.218.195.228', 161),
    'my-creds',
    timeout=300,  # in 1/100 sec
    retryCount=5
)

# Error/response receiver
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for oid, val in varBinds:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))

# Prepare and send a request message
cmdgen.GetCommandGenerator().sendVarBinds(
    snmpEngine,
    'my-router',
    None, '',   # contextEngineId, contextName
    [ ((1,3,6,1,2,1,1,1,0), None) ],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
