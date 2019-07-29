"""
Detailed VACM configuration
+++++++++++++++++++++++++++

Serves MIB subtrees under different conditions:

* Respond to SNMPv2c commands
* with SNMP community "public"
* over IPv4/UDP, listening at 127.0.0.1:161
* Serve MIB under non-default contextName `abcd` 
* Allow access to `SNMPv2-MIB::system` subtree
* Although deny access to `SNMPv2-MIB::sysUpTime` by a bit mask
* Use partial context name matching (`a`)

This example demonstrates detailed VACM configuration performed via
low-level VACM calls: `addContext`, `addVacmGroup`, `addVacmAccess`
and `addVacmView`. Each function populates one of the tables
defined in `SNMP-VIEW-BASED-ACM-MIB` and used strictly as described
in the above mentioned MIB.

The following Net-SNMP's commands will GET a value at this Agent:

| $ snmpget -v2c -c public 127.0.0.1 SNMPv2-MIB::sysLocation.0

However this command will fail:

| $ snmpget -v2c -c public 127.0.0.1 SNMPv2-MIB::sysUpTime.0

This command will not reveal `SNMPv2-MIB::sysUpTime.0` among other objects:

| $ snmpwalk -v2c -c public 127.0.0.1 SNMPv2-MIB::system
"""#
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 161))
)

# Register default MIB instrumentation controller with a new SNMP context

contextName = 'abcd'

snmpContext = context.SnmpContext(snmpEngine)

snmpContext.registerContextName(
    contextName, snmpEngine.msgAndPduDsp.mibInstrumController)

# Add new SNMP community name, map it to a new security name and
# SNMP context

securityName = 'my-area'
communityName = 'public'

config.addV1System(
    snmpEngine, securityName, communityName,
    contextEngineId=snmpContext.contextEngineId,
    contextName=contextName)

# VACM configuration settings

securityModel = 2  # SNMPv2c
securityLevel = 1  # noAuthNoPriv

vacmGroup = 'my-group'
readViewName = 'my-read-view'

# We will match by context name prefix
contextPrefix = contextName[:1]

# Populate SNMP-VIEW-BASED-ACM-MIB::vacmContextTable
config.addContext(snmpEngine, contextName)

# Populate SNMP-VIEW-BASED-ACM-MIB::vacmSecurityToGroupTable
config.addVacmGroup(
    snmpEngine, vacmGroup, securityModel, securityName)

# Populate SNMP-VIEW-BASED-ACM-MIB::vacmAccessTable
config.addVacmAccess(
    snmpEngine, vacmGroup, contextPrefix, securityModel, securityLevel,
    'prefix', readViewName, '', '')

# Populate SNMP-VIEW-BASED-ACM-MIB::vacmViewTreeFamilyTable

# Allow the whole system subtree
config.addVacmView(
    snmpEngine, readViewName, 'included', '1.3.6.1.2.1.1.1', '1.1.1.1.1.1.1.0')

# ...but exclude one sub-branch (just one scalar OID)
config.addVacmView(
    snmpEngine, readViewName, 'excluded', '1.3.6.1.2.1.1.3', '1.1.1.1.1.1.1.1')

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
snmpEngine.transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()

except Exception:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
