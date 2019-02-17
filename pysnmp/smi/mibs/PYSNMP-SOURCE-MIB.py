#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com/asn1/PYSNMP-SOURCE-MIB.txt
# Produced by pysmi-0.4.0 at Thu Feb 14 23:03:52 2019
#

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

(Integer,
 OctetString,
 ObjectIdentifier) = mibBuilder.importSymbols(
    "ASN1",
    "Integer",
    "OctetString",
    "ObjectIdentifier")

(NamedValues,) = mibBuilder.importSymbols(
    "ASN1-ENUMERATION",
    "NamedValues")

(ConstraintsIntersection,
 SingleValueConstraint,
 ValueRangeConstraint,
 ValueSizeConstraint,
 ConstraintsUnion) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT",
    "ConstraintsIntersection",
    "SingleValueConstraint",
    "ValueRangeConstraint",
    "ValueSizeConstraint",
    "ConstraintsUnion")

(pysnmpModuleIDs,) = mibBuilder.importSymbols(
    "PYSNMP-MIB",
    "pysnmpModuleIDs")

(snmpTargetAddrEntry,) = mibBuilder.importSymbols(
    "SNMP-TARGET-MIB",
    "snmpTargetAddrEntry")

(NotificationGroup,
 ModuleCompliance) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "NotificationGroup",
    "ModuleCompliance")

(Counter32,
 ModuleIdentity,
 NotificationType,
 iso,
 MibIdentifier,
 TimeTicks,
 Bits,
 Integer32,
 Counter64,
 Gauge32,
 Unsigned32,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 ObjectIdentity,
 IpAddress) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "Counter32",
    "ModuleIdentity",
    "NotificationType",
    "iso",
    "MibIdentifier",
    "TimeTicks",
    "Bits",
    "Integer32",
    "Counter64",
    "Gauge32",
    "Unsigned32",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "ObjectIdentity",
    "IpAddress")

(DisplayString,
 TAddress,
 TextualConvention) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "DisplayString",
    "TAddress",
    "TextualConvention")

pysnmpSourceMIB = ModuleIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8)
)
pysnmpSourceMIB.setRevisions(
        ("2017-04-14 00:00",
         "2015-01-16 00:00")
)
pysnmpSourceMIB.setLastUpdated("201704140000Z")
if mibBuilder.loadTexts:
    pysnmpSourceMIB.setOrganization("""\
The PySNMP Project
""")
pysnmpSourceMIB.setContactInfo("""\
E-mail: Ilya Etingof <etingof@gmail.com> GitHub:
https://github.com/etingof/pysnmp
""")
if mibBuilder.loadTexts:
    pysnmpSourceMIB.setDescription("""\
This MIB module defines implementation specific objects that provide variable
source transport endpoints feature to SNMP Engine and Standard SNMP
Applications.
""")

_PysnmpsourcemibobjectsObjectIdentity = ObjectIdentity
pysnmpSourceMIBObjects = _PysnmpsourcemibobjectsObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 1)
)
_SnmpsourceaddrtableObject = MibTable
snmpSourceAddrTable = _SnmpsourceaddrtableObject(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 1, 1)
)
if mibBuilder.loadTexts:
    snmpSourceAddrTable.setStatus("current")
if mibBuilder.loadTexts:
    snmpSourceAddrTable.setDescription("""\
A table of transport addresses to be used as a source in the generation of SNMP
messages. This table contains additional objects for the SNMP-TRANSPORT-
ADDRESS::snmpSourceAddressTable.
""")
_SnmpsourceaddrentryObject = MibTableRow
snmpSourceAddrEntry = _SnmpsourceaddrentryObject(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 1, 1, 1)
)
snmpTargetAddrEntry.registerAugmentions(
    ("PYSNMP-SOURCE-MIB",
     "snmpSourceAddrEntry")
)
snmpSourceAddrEntry.setIndexNames(*snmpTargetAddrEntry.getIndexNames())
if mibBuilder.loadTexts:
    snmpSourceAddrEntry.setStatus("current")
if mibBuilder.loadTexts:
    snmpSourceAddrEntry.setDescription("""\
A transport address to be used as a source in the generation of SNMP
operations. An entry containing additional management information applicable to
a particular target.
""")
_SnmpsourceaddrtaddressType = TAddress
_SnmpsourceaddrtaddressObject = MibTableColumn
snmpSourceAddrTAddress = _SnmpsourceaddrtaddressObject(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 1, 1, 1, 1),
    _SnmpsourceaddrtaddressType()
)
snmpSourceAddrTAddress.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpSourceAddrTAddress.setStatus("current")
if mibBuilder.loadTexts:
    snmpSourceAddrTAddress.setDescription("""\
This object contains a transport address. The format of this address depends on
the value of the snmpSourceAddrTDomain object.
""")
_PysnmpsourcemibconformanceObjectIdentity = ObjectIdentity
pysnmpSourceMIBConformance = _PysnmpsourcemibconformanceObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 2)
)
_PysnmpsourcemibcompliancesObjectIdentity = ObjectIdentity
pysnmpSourceMIBCompliances = _PysnmpsourcemibcompliancesObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 2, 1)
)
_PysnmpsourcemibgroupsObjectIdentity = ObjectIdentity
pysnmpSourceMIBGroups = _PysnmpsourcemibgroupsObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 8, 2, 2)
)

mibBuilder.exportSymbols(
    "PYSNMP-SOURCE-MIB",
    **{"pysnmpSourceMIB": pysnmpSourceMIB,
       "pysnmpSourceMIBObjects": pysnmpSourceMIBObjects,
       "snmpSourceAddrTable": snmpSourceAddrTable,
       "snmpSourceAddrEntry": snmpSourceAddrEntry,
       "snmpSourceAddrTAddress": snmpSourceAddrTAddress,
       "pysnmpSourceMIBConformance": pysnmpSourceMIBConformance,
       "pysnmpSourceMIBCompliances": pysnmpSourceMIBCompliances,
       "pysnmpSourceMIBGroups": pysnmpSourceMIBGroups}
)
