try:
    from socket import gethostname
except:
    gethostname = lambda x="": x
from time import time
from sys import version
from pysnmp import majorVersionId
from pysnmp.asn1 import subtypes

Integer, ObjectIdentifier, = mibBuilder.importSymbols(
    'ASN1', 'Integer', 'ObjectIdentifier'
    )
ModuleIdentity, ObjectIdentity, MibIdentifier, \
           MibVariable, MibTable, MibTableRow, MibTableColumn, \
           NotificationType, TimeTicks, Counter32, \
           snmpModules, mib_2 = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'ModuleIdentity', 'ObjectIdentity',
    'MibIdentifier', 'MibVariable', 'MibTable', 'MibTableRow',
    'MibTableColumn', 'NotificationType', 'TimeTicks', 'Counter32',
    'snmpModules', 'mib-2'
    )

DisplayString, TestAndIncr, TimeStamp = mibBuilder.importSymbols(
    'SNMPv2-TC', 'DisplayString', 'TestAndIncr', 'TimeStamp'
    )

snmpMIB = ModuleIdentity(snmpModules.name + (1,))
snmpMIBObjects = MibIdentifier(snmpMIB.name + (1,))
system = MibIdentifier(mib_2.name + (1,))

sysDescr = MibVariable(system.name + (1,), DisplayString("PySNMP engine version %s, Python %s" % (majorVersionId, version)).addConstraints(subtypes.ValueSizeConstraint(0, 255))).setMaxAccess('readonly')

sysObjectID = MibVariable(system.name + (2,), ObjectIdentifier((1,3,6,1,4,1,20408))).setMaxAccess('readonly')

class __SysUpTime(TimeTicks):
    initialValue = int(time())
    def get(self): return (int(time()) - TimeTicks.get(self))*100

sysUpTime = MibVariable(system.name + (3,), __SysUpTime()).setMaxAccess('readonly')

sysContact = MibVariable(system.name + (4,), DisplayString("").addConstraints(subtypes.ValueSizeConstraint(0, 255))).setMaxAccess('readonly')

sysName = MibVariable(system.name + (5,), DisplayString(gethostname()).addConstraints(subtypes.ValueSizeConstraint(0, 255))).setMaxAccess('readonly')

sysLocation = MibVariable(system.name + (6,), DisplayString("").addConstraints(subtypes.ValueSizeConstraint(0, 255))).setMaxAccess('readonly')

sysServices = MibVariable(system.name + (7,), Integer(72).addConstraints(subtypes.ValueRangeConstraint(0, 127))).setMaxAccess('readonly')

sysORLastChange = MibVariable(system.name + (8,), TimeStamp()).setMaxAccess('readonly')

# sysORTable

sysORTable = MibTable(system.name + (9,))
sysOREntry = MibTableRow(sysORTable.name + (1,)).setIndexNames((0, 'SNMPv2-MIB', 'sysORIndex'))

sysORIndex = MibTableColumn(sysOREntry.name + (1,)).setColumnInitializer(MibVariable((), Integer().addConstraints(subtypes.ValueRangeConstraint(1, 2147483647))).setMaxAccess('noaccess'))

sysORID = MibTableColumn(sysOREntry.name + (2,)).setColumnInitializer(MibVariable((), ObjectIdentifier()).setMaxAccess('readcreate'))

sysORDescr = MibTableColumn(sysOREntry.name + (3,)).setColumnInitializer(MibVariable((), DisplayString()).setMaxAccess('readcreate'))

sysORUpTime = MibTableColumn(sysOREntry.name + (4,)).setColumnInitializer(MibVariable((), TimeStamp()).setMaxAccess('readcreate'))

# the SNMP group

snmp = MibIdentifier(mib_2.name + (11,))

snmpInPkts = MibVariable(snmp.name + (1,), Counter32()).setMaxAccess('readonly')

snmpInBadVersions = MibVariable(snmp.name + (3,), Counter32()).setMaxAccess('readonly')

snmpInBadCommunityNames = MibVariable(snmp.name + (4,), Counter32()).setMaxAccess('readonly')

snmpInBadCommunityUses = MibVariable(snmp.name + (5,), Counter32()).setMaxAccess('readonly')

snmpInASNParseErrs = MibVariable(snmp.name + (6,), Counter32()).setMaxAccess('readonly')

snmpEnableAuthenTraps = MibVariable(snmp.name + (30,), Integer().addConstraints(subtypes.SingleValueConstraint(1, 2))).setMaxAccess('readwrite')

snmpSilentDrops = MibVariable(snmp.name + (31,), Counter32()).setMaxAccess('readonly')

snmpProxyDrops = MibVariable(snmp.name + (32,), Counter32()).setMaxAccess('readonly')

# information for notifications

snmpTrap = MibIdentifier(snmpMIBObjects.name + (4,))

snmpTrapOID = MibVariable(snmpTrap.name + (1,), ObjectIdentifier()).setMaxAccess('notifyonly')

snmpTrapEnterprise = MibVariable(snmpTrap.name + (3,), ObjectIdentifier()).setMaxAccess('notifyonly')

# well-known traps

snmpTraps = MibIdentifier(snmpMIBObjects.name + (5,))

coldStart = NotificationType(snmpTraps.name + (1,))

warmStart = NotificationType(snmpTraps.name + (2,))

authenticationFailure = NotificationType(snmpTraps.name + (5,))

# the set group

snmpSet = MibIdentifier(snmpMIBObjects.name + (6,))

snmpSetSerialNo = MibVariable(snmpSet.name + (1,), TestAndIncr()).setMaxAccess('readwrite')

mibBuilder.exportSymbols(
    'SNMPv2-MIB',
    snmpMIB=snmpMIB,
    snmpMIBObjects=snmpMIBObjects,
    system=system,
    sysDescr=sysDescr,
    sysObjectID=sysObjectID,
    sysUpTime=sysUpTime,
    sysContact=sysContact,
    sysName=sysName,
    sysLocation=sysLocation,
    sysServices=sysServices,
    sysORLastChange=sysORLastChange,
    sysORTable=sysORTable,
    sysOREntry=sysOREntry,
    sysORIndex=sysORIndex,
    sysORID=sysORID,
    sysORDescr=sysORDescr,
    sysORUpTime=sysORUpTime,
    snmp=snmp,
    snmpInPkts=snmpInPkts,
    snmpInBadVersions=snmpInBadVersions,
    snmpInBadCommunityNames=snmpInBadCommunityNames,
    snmpInBadCommunityUses=snmpInBadCommunityUses,
    snmpInASNParseErrs=snmpInASNParseErrs,
    snmpEnableAuthenTraps=snmpEnableAuthenTraps,
    snmpSilentDrops=snmpSilentDrops,
    snmpProxyDrops=snmpProxyDrops,
    snmpTrap=snmpTrap,
    snmpTrapOID=snmpTrapOID,
    snmpTrapEnterprise=snmpTrapEnterprise,
    snmpTraps=snmpTraps,
    coldStart=coldStart,
    warmStart=warmStart,
    authenticationFailure=authenticationFailure,
    snmpSet=snmpSet,
    snmpSetSerialNo=snmpSetSerialNo
    )
