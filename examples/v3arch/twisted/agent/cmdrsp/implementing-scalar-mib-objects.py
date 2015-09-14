"""
Implementing scalar MIB objects
+++++++++++++++++++++++++++++++

Listen and respond to SNMP GET/SET/GETNEXT/GETBULK queries with
the following options:

* SNMPv2c
* with SNMP community "public"
* serving custom Managed Object Instance defined within this script
* allow read access only to the subtree where the custom MIB object resides
* over IPv4/UDP, listening at 127.0.0.1:161
* using Twisted fraework for network transport

Either of the following Net-SNMP commands will walk this Agent:

| $ snmpwalk -v2c -c public 127.0.0.1 .1.3.6

"""#
import sys
from twisted.internet import reactor
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902
from pysnmp.carrier.twisted.dgram import udp

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTwistedTransport().openServerMode(('127.0.0.1', 161))
)

# SNMPv2c setup

# SecurityName <-> CommunityName mapping.
config.addV1System(snmpEngine, 'my-area', 'public')

# Allow read MIB access for this user / securityModels at VACM
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (1,3,6,5))

# Create an SNMP context
snmpContext = context.SnmpContext(snmpEngine)

# --- create custom Managed Object Instance ---

mibBuilder = snmpContext.getMibInstrum().getMibBuilder()

MibScalar, MibScalarInstance = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
)

class MyStaticMibScalarInstance(MibScalarInstance):
    def getValue(self, name, idx):
        return self.getSyntax().clone(
            'Python %s running on a %s platform' % (sys.version, sys.platform)
        )

mibBuilder.exportSymbols(
    '__MY_MIB', MibScalar((1,3,6,5,1), rfc1902.OctetString()),
                MyStaticMibScalarInstance((1,3,6,5,1), (0,), rfc1902.OctetString())
)

# --- end of Managed Object Instance initialization ----

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Run Twisted main loop
reactor.run()
