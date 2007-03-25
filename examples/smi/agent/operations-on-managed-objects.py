# SNMP agent backend e.g. Agent access to Managed Objects
from pysnmp.smi import builder, instrum, exval

print 'Loading MIB modules...',
mibBuilder = builder.MibBuilder().loadModules(
    'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB'
    )
print 'done'

print 'Building MIB tree...',
mibInstrum = instrum.MibInstrumController(mibBuilder)
print 'done'

print 'Remote manager write/create access to MIB instrumentation: ',
print mibInstrum.writeVars(
    (((1,3,6,1,6,3,18,1,1,1,2,109,121,110,109,115), 'mycomm'),
     ((1,3,6,1,6,3,18,1,1,1,3,109,121,110,109,115), 'mynmsname'),
     ((1,3,6,1,6,3,18,1,1,1,7,109,121,110,109,115), 'volatile'))
    )

print 'Remote manager read access to MIB instrumentation (table walk)'
oid, val = (), None
while 1:
    oid, val = mibInstrum.readNextVars(((oid, val),))[0]
    if exval.endOfMib.isSameTypeWith(val):
        break
    print oid, val

print 'Unloading MIB modules...',
mibBuilder.unloadModules()
print 'done'
