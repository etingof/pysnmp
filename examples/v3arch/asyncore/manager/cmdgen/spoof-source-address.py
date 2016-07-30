"""
Spoof source address
++++++++++++++++++++

Send a SNMP GET request
* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at 104.236.166.95:161
* from a non-local, spoofed IP 1.2.3.4 (root and Python 3.3+ required)
* for an OID in tuple form

This script performs similar to the following Net-SNMP command:

| $ snmpget -v2c -c public -ObentU 104.236.166.95 1.3.6.1.2.1.1.1.0

But unlike the above command, this script issues SNMP request from 
a non-default, non-local IP address.

It is indeed possible to originate SNMP traffic from any valid local
IP addresses. It could be a secondary IP interface, for instance. 
Superuser privileges are only required to send spoofed packets. 
Alternatively, sending from local interface could also be achieved by
binding to it (via openClientMode() parameter).

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv1 setup
#

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public')

# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 0)

#
# Setup transport endpoint and bind it with security settings yielding
# a target name
#

# Initialize asyncore-based UDP/IPv4 transport
udpSocketTransport = udp.UdpSocketTransport().openClientMode()

# Use sendmsg()/recvmsg() for socket communication (required for
# IP source spoofing functionality)
udpSocketTransport.enablePktInfo()

# Enable IP source spoofing (requires root privileges)
udpSocketTransport.enableTransparent()

# Register this transport at SNMP Engine
config.addTransport(
    snmpEngine,
    udp.domainName,
    udpSocketTransport
)

# Configure destination IPv4 address as well as source IPv4 address
config.addTargetAddr(
    snmpEngine, 'my-router',
    udp.domainName, ('104.236.166.95', 161),
    'my-creds',
    sourceAddress=('1.2.3.4', 0)
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
cmdgen.GetCommandGenerator().sendVarBinds(
    snmpEngine,
    'my-router',
    None, '',  # contextEngineId, contextName
    [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
