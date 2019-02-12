"""
Agent operations on MIB
+++++++++++++++++++++++

This script explains how SNMP Agent application manipulates
its MIB possibly triggered by SNMP Manager's commands.

"""#
from pysnmp.smi import builder
from pysnmp.smi import instrum
from pysnmp.smi import exval
from pysnmp.smi import error


def walkMib():

    def cbFun(varBinds, **context):
        err = context.get('error')
        if err:
            print(err)

        for oid, val in varBinds:
            if exval.endOfMib.isSameTypeWith(val):
                context['app']['stop'] = True

            elif not (exval.noSuchInstance.isSameTypeWith(val) or
                      exval.noSuchObject.isSameTypeWith(val)):
                print('%s = %s' % ('.'.join([str(x) for x in oid]),
                                   not val.isValue and 'N/A' or val.prettyPrint()))

            context['app']['varBinds'] = varBinds

    app_context = {
        'varBinds': [((1, 3, 6), None)],
        'stop': False
    }

    print('Read whole MIB (table walk)')

    while not app_context['stop']:
        mibInstrum.readNextMibObjects(*app_context['varBinds'], cbFun=cbFun, app=app_context)


print('Loading MIB modules...')
mibBuilder = builder.MibBuilder().loadModules(
    'SNMPv2-MIB', 'SNMP-FRAMEWORK-MIB', 'SNMP-COMMUNITY-MIB'
)

print('Building MIB tree...')
mibInstrum = instrum.MibInstrumController(mibBuilder)

walkMib()

print('Building table entry index from human-friendly representation...')
snmpCommunityEntry, = mibBuilder.importSymbols(
    'SNMP-COMMUNITY-MIB', 'snmpCommunityEntry'
)
instanceId = snmpCommunityEntry.getInstIdFromIndices('my-router')

print('Create/update some of SNMP-COMMUNITY-MIB::snmpCommunityEntry table columns: ')


def cbFun(varBinds, **context):
    err = context.get('error')
    if err:
        print(err)

    for oid, val in varBinds:
        print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))


mibInstrum.writeMibObjects(
    (snmpCommunityEntry.name + (2,) + instanceId, 'mycomm'),
    (snmpCommunityEntry.name + (3,) + instanceId, 'mynmsname'),
    (snmpCommunityEntry.name + (7,) + instanceId, 'volatile'),
    cbFun=cbFun
)

walkMib()


def cbFun(varBinds, **context):
    err = context.get('error')
    if err:
        print(err)

    for oid, val in varBinds:
        print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))


print('Destroy SNMP-COMMUNITY-MIB::snmpCommunityEntry table row via RowStatus column: ')

mibInstrum.writeMibObjects(
    (snmpCommunityEntry.name + (8,) + instanceId, 'destroy'),
    cbFun=cbFun
)

walkMib()


def cbFun(varBinds, **context):
    err = context.get('errors', None)
    if err:
        print(err)

    for oid, val in varBinds:
        print('%s = %s' % ('.'.join([str(x) for x in oid]), not val.isValue and 'N/A' or val.prettyPrint()))


print('Create SNMP-COMMUNITY-MIB::snmpCommunityEntry table row: ')

mibInstrum.writeMibObjects(
    (snmpCommunityEntry.name + (1,) + instanceId, 'mycomm'),
    (snmpCommunityEntry.name + (2,) + instanceId, 'mycomm'),
    (snmpCommunityEntry.name + (3,) + instanceId, 'mysecname'),
    (snmpCommunityEntry.name + (4,) + instanceId, 'abcdef'),
    (snmpCommunityEntry.name + (5,) + instanceId, ''),
    (snmpCommunityEntry.name + (6,) + instanceId, 'mytag'),
    (snmpCommunityEntry.name + (7,) + instanceId, 'nonVolatile'),
    (snmpCommunityEntry.name + (8,) + instanceId, 'createAndGo'),
    cbFun=cbFun
)

walkMib()

print('Destroy SNMP-COMMUNITY-MIB::snmpCommunityEntry table row via RowStatus column: ')

mibInstrum.writeMibObjects(
    (snmpCommunityEntry.name + (8,) + instanceId, 'destroy'),
    cbFun=cbFun
)

walkMib()

print('Unloading MIB modules...'),
mibBuilder.unloadModules()
