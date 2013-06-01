#
# Command Responder
#
# Listen and respond to SNMP GET/SET/GETNEXT/GETBULK queries with
# the following options:
#
# * SNMPv2c
# * with SNMP community "public"
# * serving custom Managed Objects Table Instances defined within this script
# * allow read access only to the subtree where the custom MIB objects resides
# * over IPv4/UDP, listening at 127.0.0.1:161
# 
# The following Net-SNMP's commands will populate and walk a table:
#
# $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.2.1 s 'my value'
# $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.3.1 i 4
# $ snmpwalk -v2c -c public 127.0.0.1 1.3.6
#
# ...while the following command will destroy the same row
# 
# $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.3.1 i 6
# $ snmpwalk -v2c -c public 127.0.0.1 1.3.6
#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asynsock.dgram import udp
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

# SNMPv2c setup

# SecurityName <-> CommunityName mapping.
config.addV1System(snmpEngine, 'my-area', 'public')

# Allow read MIB access for this user / securityModels at VACM
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (1,3,6,6), (1,3,6,6))

# Create an SNMP context
snmpContext = context.SnmpContext(snmpEngine)

# --- create custom Managed Objects Table Instance ---

mibBuilder = snmpContext.getMibInstrum().getMibBuilder()

( MibTable,
  MibTableRow,
  MibTableColumn,
  MibScalarInstance ) = mibBuilder.importSymbols(
    'SNMPv2-SMI', 
    'MibTable',
    'MibTableRow',
    'MibTableColumn',
    'MibScalarInstance'
  )

RowStatus, = mibBuilder.importSymbols('SNMPv2-TC', 'RowStatus')

mibBuilder.exportSymbols(
  '__MY_MIB',
  # table object
  MibTable((1,3,6,6,1)).setMaxAccess('readcreate'),
  # table row object, also carries references to table indices
  MibTableRow((1,3,6,6,1,5)).setMaxAccess('readcreate').setIndexNames((0, '__MY_MIB', 'myTableIndex')),
  # table column: value
  MibTableColumn((1,3,6,6,1,5,2), v2c.OctetString()).setMaxAccess('readcreate'),
  # table column: row status
  MibTableColumn((1,3,6,6,1,5,3), RowStatus()).setMaxAccess('readcreate'),
  # table column: index, needs to be named to refer to as index column
  myTableIndex=MibTableColumn((1,3,6,6,1,5,1), v2c.Integer()).setMaxAccess('readcreate')
)

# --- end of Managed Object Instance initialization ----

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
snmpEngine.transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
