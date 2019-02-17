#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com/asn1/PYSNMP-MIB.txt
# Produced by pysmi-0.4.0 at Thu Feb 14 10:50:29 2019
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

(NotificationGroup,
 ModuleCompliance) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "NotificationGroup",
    "ModuleCompliance")

(ObjectIdentity,
 Counter32,
 IpAddress,
 MibIdentifier,
 Gauge32,
 iso,
 Unsigned32,
 Bits,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 TimeTicks,
 Integer32,
 ModuleIdentity,
 enterprises,
 Counter64,
 NotificationType) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "ObjectIdentity",
    "Counter32",
    "IpAddress",
    "MibIdentifier",
    "Gauge32",
    "iso",
    "Unsigned32",
    "Bits",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "TimeTicks",
    "Integer32",
    "ModuleIdentity",
    "enterprises",
    "Counter64",
    "NotificationType")

(DisplayString,
 TextualConvention) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "DisplayString",
    "TextualConvention")

pysnmp = ModuleIdentity(
    (1, 3, 6, 1, 4, 1, 20408)
)
pysnmp.setRevisions(
        ("2017-04-14 00:00",
         "2005-05-14 00:00")
)
pysnmp.setLastUpdated("201704140000Z")
if mibBuilder.loadTexts:
    pysnmp.setOrganization("""\
The PySNMP Project
""")
pysnmp.setContactInfo("""\
E-mail: Ilya Etingof <etingof@gmail.com> GitHub:
https://github.com/etingof/pysnmp
""")
if mibBuilder.loadTexts:
    pysnmp.setDescription("""\
PySNMP top-level MIB tree infrastructure
""")

_PysnmpObjects_ObjectIdentity = ObjectIdentity
pysnmpObjects = _PysnmpObjects_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 1)
)
_PysnmpExamples_ObjectIdentity = ObjectIdentity
pysnmpExamples = _PysnmpExamples_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 2)
)
_PysnmpEnumerations_ObjectIdentity = ObjectIdentity
pysnmpEnumerations = _PysnmpEnumerations_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3)
)
_PysnmpModuleIDs_ObjectIdentity = ObjectIdentity
pysnmpModuleIDs = _PysnmpModuleIDs_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1)
)
_PysnmpAgentOIDs_ObjectIdentity = ObjectIdentity
pysnmpAgentOIDs = _PysnmpAgentOIDs_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 2)
)
_PysnmpDomains_ObjectIdentity = ObjectIdentity
pysnmpDomains = _PysnmpDomains_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 3)
)
_PysnmpNotificationPrefix_ObjectIdentity = ObjectIdentity
pysnmpNotificationPrefix = _PysnmpNotificationPrefix_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 4)
)
_PysnmpNotifications_ObjectIdentity = ObjectIdentity
pysnmpNotifications = _PysnmpNotifications_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 4, 0)
)
_PysnmpNotificationObjects_ObjectIdentity = ObjectIdentity
pysnmpNotificationObjects = _PysnmpNotificationObjects_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 4, 1)
)
_PysnmpConformance_ObjectIdentity = ObjectIdentity
pysnmpConformance = _PysnmpConformance_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 5)
)
_PysnmpCompliances_ObjectIdentity = ObjectIdentity
pysnmpCompliances = _PysnmpCompliances_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 5, 1)
)
_PysnmpGroups_ObjectIdentity = ObjectIdentity
pysnmpGroups = _PysnmpGroups_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 5, 2)
)
_PysnmpExperimental_ObjectIdentity = ObjectIdentity
pysnmpExperimental = _PysnmpExperimental_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 9999)
)

mibBuilder.exportSymbols(
    "PYSNMP-MIB",
    **{"pysnmp": pysnmp,
       "pysnmpObjects": pysnmpObjects,
       "pysnmpExamples": pysnmpExamples,
       "pysnmpEnumerations": pysnmpEnumerations,
       "pysnmpModuleIDs": pysnmpModuleIDs,
       "pysnmpAgentOIDs": pysnmpAgentOIDs,
       "pysnmpDomains": pysnmpDomains,
       "pysnmpNotificationPrefix": pysnmpNotificationPrefix,
       "pysnmpNotifications": pysnmpNotifications,
       "pysnmpNotificationObjects": pysnmpNotificationObjects,
       "pysnmpConformance": pysnmpConformance,
       "pysnmpCompliances": pysnmpCompliances,
       "pysnmpGroups": pysnmpGroups,
       "pysnmpExperimental": pysnmpExperimental}
)
