#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-USM-AES-MIB
# Produced by pysmi-0.4.0 at Sun Feb 17 00:00:48 2019
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

(Bits,
 Counter64,
 Integer32,
 Unsigned32,
 IpAddress,
 MibIdentifier,
 NotificationType,
 ObjectIdentity,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 ModuleIdentity,
 Counter32,
 iso,
 TimeTicks,
 snmpModules,
 Gauge32) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "Bits",
    "Counter64",
    "Integer32",
    "Unsigned32",
    "IpAddress",
    "MibIdentifier",
    "NotificationType",
    "ObjectIdentity",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "ModuleIdentity",
    "Counter32",
    "iso",
    "TimeTicks",
    "snmpModules",
    "Gauge32")

(TextualConvention,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString")

snmpUsmAesMIB = ModuleIdentity(
    (1, 3, 6, 1, 6, 3, 20)
)
snmpUsmAesMIB.setRevisions(
        ("2004-06-14 00:00",)
)
snmpUsmAesMIB.setLastUpdated("200406140000Z")
if mibBuilder.loadTexts:
    snmpUsmAesMIB.setOrganization("""\
IETF
""")
snmpUsmAesMIB.setContactInfo("""\
Uri Blumenthal Lucent Technologies / Bell Labs 67 Whippany Rd. 14D-318
Whippany, NJ 07981, USA 973-386-2163 uri@bell-labs.com Fabio Maino Andiamo
Systems, Inc. 375 East Tasman Drive San Jose, CA 95134, USA 408-853-7530
fmaino@andiamo.com Keith McCloghrie Cisco Systems, Inc. 170 West Tasman Drive
San Jose, CA 95134-1706, USA 408-526-5260 kzm@cisco.com
""")
if mibBuilder.loadTexts:
    snmpUsmAesMIB.setDescription("""\
Definitions of Object Identities needed for the use of AES by SNMP's User-based
Security Model. Copyright (C) The Internet Society (2004). This version of this
MIB module is part of RFC 3826; see the RFC itself for full legal notices.
Supplementary information may be available on
http://www.ietf.org/copyrights/ianamib.html.
""")

_UsmAesCfb128Protocol_ObjectIdentity = ObjectIdentity
usmAesCfb128Protocol = _UsmAesCfb128Protocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 2, 4)
)
if mibBuilder.loadTexts:
    usmAesCfb128Protocol.setStatus("current")
if mibBuilder.loadTexts:
    usmAesCfb128Protocol.setReference("""\
- Specification for the ADVANCED ENCRYPTION STANDARD. Federal Information
Processing Standard (FIPS) Publication 197. (November 2001). - Dworkin, M.,
NIST Recommendation for Block Cipher Modes of Operation, Methods and
Techniques. NIST Special Publication 800-38A (December 2001).
""")
if mibBuilder.loadTexts:
    usmAesCfb128Protocol.setDescription("""\
The CFB128-AES-128 Privacy Protocol.
""")

mibBuilder.exportSymbols(
    "SNMP-USM-AES-MIB",
    **{"usmAesCfb128Protocol": usmAesCfb128Protocol,
       "snmpUsmAesMIB": snmpUsmAesMIB}
)
