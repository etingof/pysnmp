"""
MIB objects to PDU var-binds
++++++++++++++++++++++++++++

This script explains how Python application (typically pysnmp-based
SNMP Manager) could turn SNMP PDU variable-bindings into MIB objects
or the other way around.

The code below does not explicitly add MIB compiler - that happens
behind the scenes. Examples below try to demo different kinds
of MIB objects to work with.
"""#
from pysnmp.smi import builder, view, rfc1902, error

# MIB Builder manages pysnmp MIBs
mibBuilder = builder.MibBuilder()

# MIB View Controller implements various queries to loaded MIBs
mibView = view.MibViewController(mibBuilder)

# Obtain MIB object information by MIB object name
mibVar = rfc1902.ObjectIdentity('IF-MIB', 'ifInOctets', 1)

# Optionally attach PySMI MIB compiler to MIB Builder that would
# create pysnmp MIBs on demand from ASN.1 sources downloaded from
# a web site.
try:
    mibVar.addAsn1MibSource('http://mibs.snmplabs.com/asn1/@mib@')
except error.SmiError:
    print('WARNING: not using MIB compiler (PySMI not installed)')

mibVar.resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain MIB object information by its [sequence] OID
mibVar = rfc1902.ObjectIdentity(tuple(mibVar)).resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain MIB object information by its [string] OID
mibVar = rfc1902.ObjectIdentity(str(mibVar)).resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain MIB object information by a mix of OID/label parts
mibVar = rfc1902.ObjectIdentity((1, 3, 6, 1, 2, 'mib-2', 1, 'sysDescr')).resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain MIB object information by a label
mibVar = rfc1902.ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.system.sysDescr').resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain the first MIB object in given MIB module
mibVar = rfc1902.ObjectIdentity('SNMPv2-MIB').resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain the last MIB object in given MIB module
mibVar = rfc1902.ObjectIdentity('SNMPv2-MIB', last=True).resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Another way to obtain the first (or last) symbol in MIB module
mibVar = rfc1902.ObjectIdentity('SNMPv2-MIB', '').resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Obtain MIB symbol from whatever MIB it is defined at (MIB should be loaded)
mibVar = rfc1902.ObjectIdentity('', 'sysDescr', 0).resolveWithMib(mibView)

print(mibVar.prettyPrint(), tuple(mibVar), str(mibVar))

# Create an OID-value pair (called variable-binding in SNMP)
varBind = rfc1902.ObjectType(
    rfc1902.ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0), '1.3.6.1'
).resolveWithMib(mibView)

print(varBind[0].prettyPrint(), varBind[1].__class__.__name__, varBind[1].prettyPrint())

# Create just OID
varBind = rfc1902.ObjectType(
    rfc1902.ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0)
).resolveWithMib(mibView)

print(varBind[0].prettyPrint(), varBind[1].__class__.__name__, varBind[1].prettyPrint())

# Create var-binds from MIB notification object (without OBJECTS clause)
varBinds = rfc1902.NotificationType(
    rfc1902.ObjectIdentity('SNMPv2-MIB', 'coldStart')
).resolveWithMib(mibView)

print(['%s = %s(%s)' % (x[0].prettyPrint(), x[1].__class__.__name__, x[1].prettyPrint()) for x in varBinds])

# Create var-binds from MIB notification object (with OBJECTS clause)
varBinds = rfc1902.NotificationType(
    rfc1902.ObjectIdentity('IF-MIB', 'linkUp'),
    instanceIndex=(1,),
    objects={('IF-MIB', 'ifOperStatus'): 'down'}
).resolveWithMib(mibView)

print(varBinds.prettyPrint())
