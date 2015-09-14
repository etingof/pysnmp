"""
Multiple SNMP Engines
+++++++++++++++++++++

Run multiple SNMP Engines each with a complete Command Responder.
Bind each SNMP Engine to a dedicated network transport endpoint:

* IPv4/UDP, listening at 127.0.0.1:161
* IPv4/UDP, listening at 127.0.0.2:161

Each Command Responder will respond to SNMP GET/SET/GETNEXT/GETBULK
queries with the following options:

* SNMPv3
* with USM user 'usr-md5-des', auth: MD5, priv DES
* allow read access to SNMPv2-MIB objects (1.3.6)
* allow write access to SNMPv2-MIB objects (1.3.6.1.2.1)

The following Net-SNMP commands will walk the first and the second
Agent respectively:

| $ snmpwalk -Ob -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 127.0.0.1 usmUserEntry
| $ snmpwalk -Ob -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 127.0.0.2 usmUserEntry

Notice differently configured snmpEngineId's in usmUserEntry columns.

"""#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp

# Configuration parameters for each of SNMP Engines
snmpEngineInfo = (
    ( '0102030405060708', udp.domainName + (0,), ('127.0.0.1', 161) ),
    ( '0807060504030201', udp.domainName + (1,), ('127.0.0.2', 161) )
)

# Instantiate the single transport dispatcher object
transportDispatcher = AsyncoreDispatcher()

# Setup a custom data routing function to select snmpEngine by transportDomain
transportDispatcher.registerRoutingCbFun(lambda td,t,d: td)

# Instantiate and configure SNMP Engines 
for snmpEngineId, transportDomain, transportAddress in snmpEngineInfo:
    # Create SNMP engine with specific engineID
    snmpEngine = engine.SnmpEngine(rfc1902.OctetString(hexValue=snmpEngineId))

    # Register SNMP Engine object with transport dispatcher. Request incoming
    # data from specific transport endpoint to be funneled to this SNMP Engine.
    snmpEngine.registerTransportDispatcher(transportDispatcher, transportDomain)

    # Transport setup

    # UDP over IPv4 
    config.addTransport(
        snmpEngine,
        transportDomain,
        udp.UdpTransport().openServerMode(transportAddress)
    )

    # SNMPv3/USM setup

    # user: usr-md5-des, auth: MD5, priv DES
    config.addV3User(
        snmpEngine, 'usr-md5-des',
        config.usmHMACMD5AuthProtocol, 'authkey1',
        config.usmDESPrivProtocol, 'privkey1'
    )

    # Allow full MIB access for this user / securityModels at VACM
    config.addVacmUser(snmpEngine, 3, 'usr-md5-des', 'authPriv', (1,3,6), (1,3,6,1,2,1)) 

    # Get default SNMP context this SNMP engine serves
    snmpContext = context.SnmpContext(snmpEngine)

    # Register SNMP Applications at the SNMP engine for particular SNMP context
    cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
    cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
    cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
    cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    transportDispatcher.runDispatcher()
except:
    transportDispatcher.closeDispatcher()
    raise
