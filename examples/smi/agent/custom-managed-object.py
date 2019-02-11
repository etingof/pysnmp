"""
Implementing MIB objects
++++++++++++++++++++++++

This script explains how SNMP Agent application could model
real-world data as Managed Objects defined in MIB.

"""#
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
    # noinspection PyUnusedLocal
    def readGet(self, varBind, **context):
        cbFun = context['cbFun']

        # Just return a custom value
        cbFun((varBind[0], self.syntax.clone('The Leaky Cauldron')), **context)


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


    def cbFun(varBinds, **context):

        for oid, val in varBinds:

            if exval.endOfMib.isSameTypeWith(val):
                context['app']['stop'] = True

            print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))

        context['app']['varBinds'] = varBinds


    app_context = {
        'varBinds': [((1, 3, 6), None)],
        'stop': False
    }

    print('Remote manager read access to MIB instrumentation (table walk)')

    while not app_context['stop']:
        mibInstrum.readNextMibObjects(*app_context['varBinds'], cbFun=cbFun, app=app_context)

    print('done')
