#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-USER-BASED-SM-3DES-MIB
# Produced by pysmi-0.4.0 at Sat Feb 16 23:20:21 2019
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

(snmpPrivProtocols,) = mibBuilder.importSymbols(
    "SNMP-FRAMEWORK-MIB",
    "snmpPrivProtocols")

(NotificationGroup,
 ModuleCompliance) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "NotificationGroup",
    "ModuleCompliance")

(snmpModules,
 TimeTicks,
 NotificationType,
 ModuleIdentity,
 Integer32,
 Gauge32,
 MibIdentifier,
 iso,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 IpAddress,
 Unsigned32,
 Bits,
 Counter32,
 Counter64,
 ObjectIdentity) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "snmpModules",
    "TimeTicks",
    "NotificationType",
    "ModuleIdentity",
    "Integer32",
    "Gauge32",
    "MibIdentifier",
    "iso",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "IpAddress",
    "Unsigned32",
    "Bits",
    "Counter32",
    "Counter64",
    "ObjectIdentity")

(TextualConvention,
 DisplayString,
 AutonomousType) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString",
    "AutonomousType")


# MODULE-IDENTITY

snmpUsmMIB = ModuleIdentity(
    (1, 3, 6, 1, 6, 3, 15)
)
snmpUsmMIB.setRevisions(
        ("1999-10-06 00:00",)
)
snmpUsmMIB.setLastUpdated("9910060000Z")
if mibBuilder.loadTexts:
    snmpUsmMIB.setOrganization("""\
SNMPv3 Working Group
""")
snmpUsmMIB.setContactInfo("""\
WG-email: snmpv3@lists.tislabs.com Subscribe: majordomo@lists.tislabs.com In
msg body: subscribe snmpv3 Chair: Russ Mundy NAI Labs postal: 3060 Washington
Rd Glenwood MD 21738 USA email: mundy@tislabs.com phone: +1-443-259-2307 Co-
editor: David Reeder NAI Labs postal: 3060 Washington Road (Route 97) Glenwood,
MD 21738 USA email: dreeder@tislabs.com phone: +1-443-259-2348 Co-editor:
Olafur Gudmundsson NAI Labs postal: 3060 Washington Road (Route 97) Glenwood,
MD 21738 USA email: ogud@tislabs.com phone: +1-443-259-2389
""")
if mibBuilder.loadTexts:
    snmpUsmMIB.setDescription("""\
Extension to the SNMP User-based Security Model to support Triple-DES EDE in
'Outside' CBC (cipher-block chaining) Mode.
""")

_Usm3DESEDEPrivProtocol_ObjectIdentity = ObjectIdentity
usm3DESEDEPrivProtocol = _Usm3DESEDEPrivProtocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 2, 3)
)
if mibBuilder.loadTexts:
    usm3DESEDEPrivProtocol.setStatus("current")
if mibBuilder.loadTexts:
    usm3DESEDEPrivProtocol.setReference("- Data Encryption Standard, National Institute of Standards and Technology. Federal Information Processing Standard (FIPS) Publication 46-3, (1999, pending approval). Will supersede FIPS Publication 46-2. - Data Encryption Algorithm, American National Standards Institute. ANSI X3.92-1981, (December, 1980). - DES Modes of Operation, National Institute of Standards and Technology. Federal Information Processing Standard (FIPS) Publication 81, (December, 1980). - Data Encryption Algorithm - Modes of Operation, American National Standards Institute. ANSI X3.106-1983, (May 1983). ")
if mibBuilder.loadTexts:
    usm3DESEDEPrivProtocol.setDescription("""\
The 3DES-EDE Symmetric Encryption Protocol.
""")

mibBuilder.exportSymbols(
    "SNMP-USER-BASED-SM-3DES-MIB",
    **{"usm3DESEDEPrivProtocol": usm3DESEDEPrivProtocol,
       "snmpUsmMIB": snmpUsmMIB}
)
