"""
Custom MIB Controller
+++++++++++++++++++++

Listen and respond to SNMP GET/SET/GETNEXT/GETBULK queries with
the following options:

* SNMPv3
* with USM username usr-none-none
* using alternative set of Managed Objects addressed by 
  contextName: my-context
* allow access to SNMPv2-MIB objects (1.3.6.1.2.1)
* over IPv4/UDP, listening at 127.0.0.1:161

The following Net-SNMP command will send GET request to this Agent:

| $ snmpget -v3 -u usr-none-none -l noAuthNoPriv -n my-context -Ir 127.0.0.1 sysDescr.0

"""#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.smi import instrum
from pysnmp.proto.api import v2c

# Create SNMP engine
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 161))
)

# SNMPv3/USM setup

# user: usr-none-none, auth: NONE, priv NONE
config.addV3User(
    snmpEngine, 'usr-none-none'
)

# Allow full MIB access for each user at VACM
config.addVacmUser(snmpEngine, 3, 'usr-none-none', 'noAuthNoPriv', (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))

# Create an SNMP context
snmpContext = context.SnmpContext(snmpEngine)


# Very basic Management Instrumentation Controller without
# any Managed Objects attached. It supports only GET's and
# always echos request var-binds in response.
class EchoMibInstrumController(instrum.AbstractMibInstrumController):
    def readVars(self, varBinds, acInfo=(None, None)):
        return [(ov[0], v2c.OctetString('You queried OID %s' % ov[0])) for ov in varBinds]


# Create a custom Management Instrumentation Controller and register at
# SNMP Context under ContextName 'my-context'
snmpContext.registerContextName(
    v2c.OctetString('my-context'),  # Context Name
    EchoMibInstrumController()  # Management Instrumentation
)

# Register GET&SET Applications at the SNMP engine for a custom SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
snmpEngine.transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
