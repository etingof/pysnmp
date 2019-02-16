#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-MPD-MIB
# Produced by pysmi-0.4.0 at Sat Feb 16 12:09:00 2019
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

# Import SMI symbols from the MIBs this MIB depends on

(ObjectGroup,
 ModuleCompliance,
 NotificationGroup) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "ObjectGroup",
    "ModuleCompliance",
    "NotificationGroup")

(ObjectIdentity,
 Unsigned32,
 snmpModules,
 Bits,
 MibIdentifier,
 Counter32,
 IpAddress,
 Gauge32,
 ModuleIdentity,
 Integer32,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 NotificationType,
 iso,
 TimeTicks,
 Counter64) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "ObjectIdentity",
    "Unsigned32",
    "snmpModules",
    "Bits",
    "MibIdentifier",
    "Counter32",
    "IpAddress",
    "Gauge32",
    "ModuleIdentity",
    "Integer32",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "NotificationType",
    "iso",
    "TimeTicks",
    "Counter64")

(TextualConvention,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString")

snmpMPDMIB = ModuleIdentity(
    (1, 3, 6, 1, 6, 3, 11)
)
snmpMPDMIB.setRevisions(
        ("2002-10-14 00:00",
         "1999-05-04 16:36",
         "1997-09-30 00:00")
)
snmpMPDMIB.setLastUpdated("200210140000Z")
if mibBuilder.loadTexts:
    snmpMPDMIB.setOrganization("""\
SNMPv3 Working Group
""")
snmpMPDMIB.setContactInfo("""\
WG-EMail: snmpv3@lists.tislabs.com Subscribe: snmpv3-request@lists.tislabs.com
Co-Chair: Russ Mundy Network Associates Laboratories postal: 15204 Omega Drive,
Suite 300 Rockville, MD 20850-4601 USA EMail: mundy@tislabs.com phone: +1
301-947-7107 Co-Chair & Co-editor: David Harrington Enterasys Networks postal:
35 Industrial Way P. O. Box 5005 Rochester NH 03866-5005 USA EMail:
dbh@enterasys.com phone: +1 603-337-2614 Co-editor: Jeffrey Case SNMP Research,
Inc. postal: 3001 Kimberlin Heights Road Knoxville, TN 37920-9716 USA EMail:
case@snmp.com phone: +1 423-573-1434 Co-editor: Randy Presuhn BMC Software,
Inc. postal: 2141 North First Street San Jose, CA 95131 USA EMail:
randy_presuhn@bmc.com phone: +1 408-546-1006 Co-editor: Bert Wijnen Lucent
Technologies postal: Schagen 33 3461 GL Linschoten Netherlands EMail:
bwijnen@lucent.com phone: +31 348-680-485
""")
if mibBuilder.loadTexts:
    snmpMPDMIB.setDescription("""\
The MIB for Message Processing and Dispatching Copyright (C) The Internet
Society (2002). This version of this MIB module is part of RFC 3412; see the
RFC itself for full legal notices.
""")

_SnmpMPDAdmin_ObjectIdentity = ObjectIdentity
snmpMPDAdmin = _SnmpMPDAdmin_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 1)
)
_SnmpMPDMIBObjects_ObjectIdentity = ObjectIdentity
snmpMPDMIBObjects = _SnmpMPDMIBObjects_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 2)
)
_SnmpMPDStats_ObjectIdentity = ObjectIdentity
snmpMPDStats = _SnmpMPDStats_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 2, 1)
)
_SnmpUnknownSecurityModels_Type = Counter32
_SnmpUnknownSecurityModels_Object = MibScalar
snmpUnknownSecurityModels = _SnmpUnknownSecurityModels_Object(
    (1, 3, 6, 1, 6, 3, 11, 2, 1, 1),
    _SnmpUnknownSecurityModels_Type()
)
snmpUnknownSecurityModels.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    snmpUnknownSecurityModels.setStatus("current")
if mibBuilder.loadTexts:
    snmpUnknownSecurityModels.setDescription("""\
The total number of packets received by the SNMP engine which were dropped
because they referenced a securityModel that was not known to or supported by
the SNMP engine.
""")
_SnmpInvalidMsgs_Type = Counter32
_SnmpInvalidMsgs_Object = MibScalar
snmpInvalidMsgs = _SnmpInvalidMsgs_Object(
    (1, 3, 6, 1, 6, 3, 11, 2, 1, 2),
    _SnmpInvalidMsgs_Type()
)
snmpInvalidMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    snmpInvalidMsgs.setStatus("current")
if mibBuilder.loadTexts:
    snmpInvalidMsgs.setDescription("""\
The total number of packets received by the SNMP engine which were dropped
because there were invalid or inconsistent components in the SNMP message.
""")
_SnmpUnknownPDUHandlers_Type = Counter32
_SnmpUnknownPDUHandlers_Object = MibScalar
snmpUnknownPDUHandlers = _SnmpUnknownPDUHandlers_Object(
    (1, 3, 6, 1, 6, 3, 11, 2, 1, 3),
    _SnmpUnknownPDUHandlers_Type()
)
snmpUnknownPDUHandlers.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    snmpUnknownPDUHandlers.setStatus("current")
if mibBuilder.loadTexts:
    snmpUnknownPDUHandlers.setDescription("""\
The total number of packets received by the SNMP engine which were dropped
because the PDU contained in the packet could not be passed to an application
responsible for handling the pduType, e.g. no SNMP application had registered
for the proper combination of the contextEngineID and the pduType.
""")
_SnmpMPDMIBConformance_ObjectIdentity = ObjectIdentity
snmpMPDMIBConformance = _SnmpMPDMIBConformance_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 3)
)
_SnmpMPDMIBCompliances_ObjectIdentity = ObjectIdentity
snmpMPDMIBCompliances = _SnmpMPDMIBCompliances_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 3, 1)
)
_SnmpMPDMIBGroups_ObjectIdentity = ObjectIdentity
snmpMPDMIBGroups = _SnmpMPDMIBGroups_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 11, 3, 2)
)

snmpMPDGroup = ObjectGroup(
    (1, 3, 6, 1, 6, 3, 11, 3, 2, 1)
)
snmpMPDGroup.setObjects(
      *(("SNMP-MPD-MIB", "snmpUnknownSecurityModels"),
        ("SNMP-MPD-MIB", "snmpInvalidMsgs"),
        ("SNMP-MPD-MIB", "snmpUnknownPDUHandlers"))
)
if mibBuilder.loadTexts:
    snmpMPDGroup.setStatus("current")
if mibBuilder.loadTexts:
    snmpMPDGroup.setDescription("""\
A collection of objects providing for remote monitoring of the SNMP Message
Processing and Dispatching process.
""")


snmpMPDCompliance = ModuleCompliance(
    (1, 3, 6, 1, 6, 3, 11, 3, 1, 1)
)
if mibBuilder.loadTexts:
    snmpMPDCompliance.setStatus(
        "current"
    )
if mibBuilder.loadTexts:
    snmpMPDCompliance.setDescription("""\
The compliance statement for SNMP entities which implement the SNMP-MPD-MIB.
""")

mibBuilder.exportSymbols(
    "SNMP-MPD-MIB",
    **{"snmpMPDMIB": snmpMPDMIB,
       "snmpMPDAdmin": snmpMPDAdmin,
       "snmpMPDMIBObjects": snmpMPDMIBObjects,
       "snmpMPDStats": snmpMPDStats,
       "snmpUnknownSecurityModels": snmpUnknownSecurityModels,
       "snmpInvalidMsgs": snmpInvalidMsgs,
       "snmpUnknownPDUHandlers": snmpUnknownPDUHandlers,
       "snmpMPDMIBConformance": snmpMPDMIBConformance,
       "snmpMPDMIBCompliances": snmpMPDMIBCompliances,
       "snmpMPDCompliance": snmpMPDCompliance,
       "snmpMPDMIBGroups": snmpMPDMIBGroups,
       "snmpMPDGroup": snmpMPDGroup}
)
