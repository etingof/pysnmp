"""
SNMP MIB browser
++++++++++++++++

This script explains how Python application (typically SNMP Manager)
could load SNMP MIB modules into memory and introspect Managed Objects
defined in MIB.

"""#
from pysnmp.smi import builder, view, compiler, error

# Create MIB loader/builder
mibBuilder = builder.MibBuilder()

# Optionally attach PySMI MIB compiler (if installed)
#print('Attaching MIB compiler...'),
#compiler.addMibCompiler(mibBuilder, sources=['/usr/share/snmp/mibs'])
#print('done')

# Optionally set an alternative path to compiled MIBs
print('Setting MIB sources...')
mibBuilder.addMibSources(builder.DirMibSource('/opt/pysnmp_mibs'))
print(mibBuilder.getMibSources())
print('done')

print('Loading MIB modules...'),
mibBuilder.loadModules(
    'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB', 'IP-MIB'
    )
print('done')

print('Indexing MIB objects...'),
mibView = view.MibViewController(mibBuilder)
print('done')

print('MIB symbol name lookup by OID: '),
oid, label, suffix = mibView.getNodeName((1,3,6,1,2,1,1,1))
print(oid, label, suffix)

print('MIB symbol name lookup by label: '),
oid, label, suffix = mibView.getNodeName((1,3,6,1,2,'mib-2',1,'sysDescr'))
print(oid, label, suffix)

print('MIB symbol name lookup by symbol description: '),
oid, label, suffix = mibView.getNodeName(('sysDescr',))
oid, label, suffix = mibView.getNodeName(('snmpEngineID',), 'SNMP-FRAMEWORK-MIB')
print(oid, label, suffix)

print('MIB object value pretty print: '),
mibNode, = mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')
print(mibNode.syntax.prettyPrint())

print('MIB symbol location lookup by name: '),
modName, symName, suffix = mibView.getNodeLocation(('snmpCommunityEntry',))
print(symName, modName)

print('MIB node lookup by location: '),
rowNode, = mibBuilder.importSymbols(modName, symName)
print(rowNode)

print('Conceptual table index value to oid conversion: '),
oid = rowNode.getInstIdFromIndices('router')
print(oid)
print('Conceptual table index oid to value conversion: '),
print(rowNode.getIndicesFromInstId(oid))

print('MIB tree traversal')
oid, label, suffix = mibView.getFirstNodeName()
while 1:
    try:
        modName, nodeDesc, suffix = mibView.getNodeLocation(oid)
        print('%s::%s == %s' % (modName, nodeDesc, oid))
        oid, label, suffix = mibView.getNextNodeName(oid)
    except error.NoSuchObjectError:
        break

print('Modules traversal')
modName = mibView.getFirstModuleName()
while 1:
    if modName: print(modName)
    try:
        modName = mibView.getNextModuleName(modName)
    except error.SmiError:
        break
