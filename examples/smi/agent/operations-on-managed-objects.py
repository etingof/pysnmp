# SNMP agent backend e.g. Agent access to Managed Objects
from pysnmp.smi import builder, instrum, exval

print('Loading MIB modules...'),
mibBuilder = builder.MibBuilder().loadModules(
    'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB'
    )
print('done')

print('Building MIB tree...'),
mibInstrum = instrum.MibInstrumController(mibBuilder)
print('done')

print('Building table entry index from human-friendly representation...'),
snmpCommunityEntry, = mibBuilder.importSymbols(
    'SNMP-COMMUNITY-MIB', 'snmpCommunityEntry'
)
instanceId = snmpCommunityEntry.getInstIdFromIndices('my-router')
print('done')

print('Create/update SNMP-COMMUNITY-MIB::snmpCommunityEntry table row: ')
varBinds = mibInstrum.writeVars(
    ( (snmpCommunityEntry.name+(2,)+instanceId, 'mycomm'),
      (snmpCommunityEntry.name+(3,)+instanceId, 'mynmsname'),
      (snmpCommunityEntry.name+(7,)+instanceId, 'volatile') )
)
for oid, val in varBinds:
    print('%s = %s' % ('.'.join([str(x) for x in oid]), val.prettyPrint()))
print('done')

print('Read whole MIB (table walk)')
oid, val = (), None
while 1:
    oid, val = mibInstrum.readNextVars(((oid, val),))[0]
    if exval.endOfMib.isSameTypeWith(val):
        break
    print('%s = %s' % ('.'.join([str(x) for x in oid]), val.prettyPrint()))
print('done')

print('Unloading MIB modules...'),
mibBuilder.unloadModules()
print('done')
