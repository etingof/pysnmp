# Managed Objects implementation
from pysnmp.smi import builder

# MIB Builder is normally pre-created by SNMP engine
mibBuilder = builder.MibBuilder()

#
# This may be done in a stand-alone file and then loaded up
# by SNMP Agent
#

# A base class for a custom Managed Object
MibScalarInstance, = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'MibScalarInstance'
    )

# Managed object specification
sysLocation, = mibBuilder.importSymbols('SNMPv2-MIB', 'sysLocation')

# Custom Managed Object
class MySysLocationInstance(MibScalarInstance):
    def readGet(self, name, *args):
        # Just return a custom value
        return name, self.syntax.clone('The Leaky Cauldron')
    
sysLocationInstance = MySysLocationInstance(
    sysLocation.name, (0,), sysLocation.syntax
    )

# Register Managed Object with a MIB tree
mibBuilder.exportSymbols(
    # '__' prefixed MIB modules take precedence on indexing
    '__MY-LOCATION-MIB', sysLocationInstance=sysLocationInstance
    )

if __name__ == '__main__':
    #
    # This is what is done internally by Agent.
    #
    from pysnmp.smi import instrum, exval

    mibInstrum = instrum.MibInstrumController(mibBuilder)

    print('Remote manager read access to MIB instrumentation (table walk)')
    oid, val = (), None
    while 1:
        oid, val = mibInstrum.readNextVars(((oid, val),))[0]
        if exval.endOfMib.isSameTypeWith(val):
            break
        print(oid, val.prettyPrint())
