"""
PDU var-binds to MIB objects
++++++++++++++++++++++++++++

This script explains how Python application could turn SNMP PDU
variable-bindings into MIB objects or the other way around.

The code that configures MIB compiler is similar to what
happens inside the pysnmp.hlapi API.
"""#
from pysnmp.smi import builder, view, compiler, rfc1902

# Assemble MIB browser
mibBuilder = builder.MibBuilder()
mibViewController = view.MibViewController(mibBuilder)
compiler.addMibCompiler(mibBuilder, sources=['file:///usr/share/snmp/mibs',
                                             'http://mibs.snmplabs.com/asn1/@mib@'])

# Pre-load MIB modules we expect to work with
mibBuilder.loadModules('SNMPv2-MIB', 'SNMP-COMMUNITY-MIB')

# This is what we can get in TRAP PDU
varBinds = [
    ('1.3.6.1.2.1.1.3.0', 12345),
    ('1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.6.3.1.1.5.2'),
    ('1.3.6.1.6.3.18.1.3.0', '0.0.0.0'),
    ('1.3.6.1.6.3.18.1.4.0', ''),
    ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
    ('1.3.6.1.2.1.1.1.0', 'my system')
]

# Run var-binds through MIB resolver
# You may want to catch and ignore resolution errors here
varBinds = [rfc1902.ObjectType(rfc1902.ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds]

for varBind in varBinds:
    print(varBind.prettyPrint())
