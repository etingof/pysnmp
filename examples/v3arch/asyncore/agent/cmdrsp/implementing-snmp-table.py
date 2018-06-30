"""
Implementing conceptual table
+++++++++++++++++++++++++++++

Listen and respond to SNMP GET/SET/GETNEXT/GETBULK queries with
the following options:

* SNMPv2c
* with SNMP community "public"
* define a simple SNMP Table within a newly created EXAMPLE-MIB
* pre-populate SNMP Table with a single row of values
* allow read access only to the subtree where example SNMP Table resides
* over IPv4/UDP, listening at 127.0.0.1:161
 
The following Net-SNMP commands will populate and walk a table:

| $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.2.97.98.99 s "my value"
| $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.4.97.98.99 i 4
| $ snmpwalk -v2c -c public 127.0.0.1 1.3.6

...while the following command will destroy the same row

| $ snmpset -v2c -c public 127.0.0.1 1.3.6.6.1.5.4.97.98.99 i 6
| $ snmpwalk -v2c -c public 127.0.0.1 1.3.6

"""#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
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
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (1, 3, 6, 6), (1, 3, 6, 6))

# Create an SNMP context
snmpContext = context.SnmpContext(snmpEngine)

# --- define custom SNMP Table within a newly defined EXAMPLE-MIB ---

mibBuilder = snmpContext.getMibInstrum().getMibBuilder()

(MibTable,
 MibTableRow,
 MibTableColumn,
 MibScalarInstance) = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibTable',
    'MibTableRow',
    'MibTableColumn',
    'MibScalarInstance'
)

RowStatus, = mibBuilder.importSymbols('SNMPv2-TC', 'RowStatus')

mibBuilder.exportSymbols(
    '__EXAMPLE-MIB',
    # table object
    exampleTable=MibTable((1, 3, 6, 6, 1)).setMaxAccess('readcreate'),
    # table row object, also carries references to table indices
    exampleTableEntry=MibTableRow((1, 3, 6, 6, 1, 5)).setMaxAccess('readcreate').setIndexNames((0, '__EXAMPLE-MIB', 'exampleTableColumn1')),
    # table column: string index
    exampleTableColumn1=MibTableColumn((1, 3, 6, 6, 1, 5, 1), v2c.OctetString()).setMaxAccess('readcreate'),
    # table column: string value
    exampleTableColumn2=MibTableColumn((1, 3, 6, 6, 1, 5, 2), v2c.OctetString()).setMaxAccess('readcreate'),
    # table column: integer value with default
    exampleTableColumn3=MibTableColumn((1, 3, 6, 6, 1, 5, 3), v2c.Integer32(123)).setMaxAccess('readcreate'),
    # table column: row status
    exampleTableStatus=MibTableColumn((1, 3, 6, 6, 1, 5, 4), RowStatus('notExists')).setMaxAccess('readcreate')
)

# --- end of custom SNMP table definition, empty table now exists ---

# --- populate custom SNMP table with one row ---

(exampleTableEntry,
 exampleTableColumn2,
 exampleTableColumn3,
 exampleTableStatus) = mibBuilder.importSymbols(
    '__EXAMPLE-MIB',
    'exampleTableEntry',
    'exampleTableColumn2',
    'exampleTableColumn3',
    'exampleTableStatus'
)
rowInstanceId = exampleTableEntry.getInstIdFromIndices('example record one')
mibInstrumentation = snmpContext.getMibInstrum()
mibInstrumentation.writeVars(
    (exampleTableColumn2.name + rowInstanceId, 'my string value'),
    (exampleTableColumn3.name + rowInstanceId, 123456),
    (exampleTableStatus.name + rowInstanceId, 'createAndGo')
)

# --- end of SNMP table population ---

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
