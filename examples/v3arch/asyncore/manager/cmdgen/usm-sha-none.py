"""
Set string value
++++++++++++++++

Send a SNMP SET request with the following options:

* with SNMPv3 with user 'usr-sha-none', SHA auth and no privacy protocols
* over IPv4/UDP
* to an Agent at 104.236.166.95:161
* for an OID in tuple form and a string-typed value

This script performs similar to the following Net-SNMP command:

| $ snmpset -v3 -l authNoPriv -u usr-sha-none -a SHA -A authkey1 -ObentU 104.236.166.95:161 1.3.6.1.2.1.1.9.1.3.1 s 'my new value'

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import rfc1902

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv3/USM setup
#

# user: usr-sha-none, auth: SHA, priv none
config.addV3User(
    snmpEngine, 'usr-sha-none',
    config.usmHMACSHAAuthProtocol, 'authkey1'
)
config.addTargetParams(snmpEngine, 'my-creds', 'usr-sha-none', 'authNoPriv')

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
    elif errorStatus:
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
    [((1, 3, 6, 1, 2, 1, 1, 9, 1, 3, 1), rfc1902.OctetString('my new value'))],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
