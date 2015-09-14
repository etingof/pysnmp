"""
Report SNMP engine processing details
+++++++++++++++++++++++++++++++++++++

Send SNMP GET request with the following options:

* with SNMPv3 with user 'usr-sha-aes', SHA auth and AES128 privacy protocols
* over IPv4/UDP
* to an Agent at 195.218.195.228:161
* for an OID in tuple form
* also registers its own execution observer to snmpEngine

While execution, this script will report some details on request processing 
as seen by rfc3412.sendPdu() and rfc3412.receiveMessage() abstract interfaces.

This script performs similar to the following Net-SNMP command:

| $ snmpget -v3 -l authPriv -u usr-sha-aes -a SHA -A authkey1 -x AES -X privkey1 -ObentU 195.218.195.228:161  1.3.6.1.2.1.1.1.0

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# Execution point observer setup

# Register a callback to be invoked at specified execution point of 
# SNMP Engine and passed local variables at code point's local scope
def requestObserver(snmpEngine, execpoint, variables, cbCtx):
    print('Execution point: %s' % execpoint)
    print('* transportDomain: %s' % '.'.join([str(x) for x in variables['transportDomain']]))
    print('* transportAddress: %s' % '@'.join([str(x) for x in variables['transportAddress']]))
    print('* securityModel: %s' % variables['securityModel'])
    print('* securityName: %s' % variables['securityName'])
    print('* securityLevel: %s' % variables['securityLevel'])
    print('* contextEngineId: %s' % (variables['contextEngineId'] and variables['contextEngineId'].prettyPrint() or '<empty>',))
    print('* contextName: %s' % variables['contextName'].prettyPrint())
    print('* PDU: %s' % variables['pdu'].prettyPrint())

snmpEngine.observer.registerObserver(
    requestObserver, 
    'rfc3412.sendPdu',
    'rfc3412.receiveMessage:response'
)

#
# SNMPv3/USM setup
#

# user: usr-sha-aes, auth: SHA, priv AES
config.addV3User(
    snmpEngine, 'usr-sha-aes',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1'
)
config.addTargetParams(snmpEngine, 'my-creds', 'usr-sha-aes', 'authPriv')

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
    'my-creds'
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
    None, '',  # contextEngineId, contextName
    [ ((1,3,6,1,2,1,1,1,0), None) ],
    cbFun
)

# Run I/O dispatcher which would send pending queries and process responses
snmpEngine.transportDispatcher.runDispatcher()

snmpEngine.observer.unregisterObserver()
