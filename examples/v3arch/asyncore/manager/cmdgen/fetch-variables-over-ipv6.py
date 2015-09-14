"""
Walk Agent over IPv6
++++++++++++++++++++

Send a series of SNMP GETNEXT requests with the following options:

* with SNMPv3 with user 'usr-md5-none', MD5 auth and no privacy protocols
* over IPv6/UDP
* to an Agent at [::1]:161
* for two OIDs in tuple form
* stop on end-of-mib condition for both OIDs

This script performs similar to the following Net-SNMP command:

| $ snmpwalk -v3 -l authNoPriv -u usr-md5-none -A authkey1 -ObentU udp6:[::1]:161 1.3.6.1.2.1.1 1.3.6.1.4.1.1

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp6
from pysnmp.entity.rfc3413 import cmdgen

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

#
# SNMPv3/USM setup
#

# user: usr-md5-des, auth: MD5, priv NONE
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)
config.addTargetParams(snmpEngine, 'my-creds', 'usr-md5-none', 'authNoPriv')

#
# Setup transport endpoint and bind it with security settings yielding
# a target name
#

# UDP/IPv6
config.addTransport(
    snmpEngine,
    udp6.domainName,
    udp6.Udp6SocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-router',
    udp6.domainName, ('::1', 161),
    'my-creds'
)

# Error/response receiver
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):
    if errorIndication:
        print(errorIndication)
        return
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
        return  # stop on error
    for varBindRow in varBindTable:
        for oid, val in varBindRow:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
    return True # signal dispatcher to continue

# Prepare initial request to be sent
cmdgen.NextCommandGenerator().sendVarBinds(
    snmpEngine,
    'my-router',
    None, '',  # contextEngineId, contextName
    [ ((1,3,6,1,2,1,1), None),
      ((1,3,6,1,4,1,1), None) ],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()
