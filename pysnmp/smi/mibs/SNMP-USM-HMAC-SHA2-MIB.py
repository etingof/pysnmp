#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-USM-HMAC-SHA2-MIB
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

(snmpAuthProtocols,) = mibBuilder.importSymbols(
    "SNMP-FRAMEWORK-MIB",
    "snmpAuthProtocols")

(ModuleCompliance,
 NotificationGroup) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "ModuleCompliance",
    "NotificationGroup")

(mib_2,
 Gauge32,
 NotificationType,
 Unsigned32,
 ModuleIdentity,
 iso,
 Counter32,
 TimeTicks,
 Counter64,
 IpAddress,
 ObjectIdentity,
 Bits,
 Integer32,
 MibIdentifier,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "mib-2",
    "Gauge32",
    "NotificationType",
    "Unsigned32",
    "ModuleIdentity",
    "iso",
    "Counter32",
    "TimeTicks",
    "Counter64",
    "IpAddress",
    "ObjectIdentity",
    "Bits",
    "Integer32",
    "MibIdentifier",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn")

(TextualConvention,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString")

snmpUsmHmacSha2MIB = ModuleIdentity(
    (1, 3, 6, 1, 2, 1, 235)
)
snmpUsmHmacSha2MIB.setRevisions(
        ("2016-04-18 00:00",
         "2015-10-14 00:00")
)
snmpUsmHmacSha2MIB.setLastUpdated("201604180000Z")
if mibBuilder.loadTexts:
    snmpUsmHmacSha2MIB.setOrganization("""\
SNMPv3 Working Group
""")
snmpUsmHmacSha2MIB.setContactInfo("""\
WG email: OPSAWG@ietf.org Subscribe:
https://www.ietf.org/mailman/listinfo/opsawg Editor: Johannes Merkle secunet
Security Networks Postal: Mergenthaler Allee 77 D-65760 Eschborn Germany Phone:
+49 20154543091 Email: johannes.merkle@secunet.com Co-Editor: Manfred Lochter
Bundesamt fuer Sicherheit in der Informationstechnik (BSI) Postal: Postfach
200363 D-53133 Bonn Germany Phone: +49 228 9582 5643 Email:
manfred.lochter@bsi.bund.de
""")
if mibBuilder.loadTexts:
    snmpUsmHmacSha2MIB.setDescription("""\
Definitions of Object Identities needed for the use of HMAC-SHA2 Authentication
Protocols by SNMP's User-based Security Model. Copyright (c) 2016 IETF Trust
and the persons identified as authors of the code. All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license terms
contained in, the Simplified BSD License set forth in Section 4.c of the IETF
Trust's Legal Provisions Relating to IETF Documents (http://trustee.ietf.org
/license-info).
""")

_UsmHMAC128SHA224AuthProtocol_ObjectIdentity = ObjectIdentity
usmHMAC128SHA224AuthProtocol = _UsmHMAC128SHA224AuthProtocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 1, 4)
)
if mibBuilder.loadTexts:
    usmHMAC128SHA224AuthProtocol.setStatus("current")
if mibBuilder.loadTexts:
    usmHMAC128SHA224AuthProtocol.setReference("""\
- Krawczyk, H., Bellare, M., and R. Canetti, HMAC: Keyed-Hashing for Message
Authentication, RFC 2104. - National Institute of Standards and Technology,
Secure Hash Standard (SHS), FIPS PUB 180-4, 2012.
""")
if mibBuilder.loadTexts:
    usmHMAC128SHA224AuthProtocol.setDescription("""\
The Authentication Protocol usmHMAC128SHA224AuthProtocol uses HMAC-SHA-224 and
truncates output to 128 bits.
""")
_UsmHMAC192SHA256AuthProtocol_ObjectIdentity = ObjectIdentity
usmHMAC192SHA256AuthProtocol = _UsmHMAC192SHA256AuthProtocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 1, 5)
)
if mibBuilder.loadTexts:
    usmHMAC192SHA256AuthProtocol.setStatus("current")
if mibBuilder.loadTexts:
    usmHMAC192SHA256AuthProtocol.setReference("""\
- Krawczyk, H., Bellare, M., and R. Canetti, HMAC: Keyed-Hashing for Message
Authentication, RFC 2104. - National Institute of Standards and Technology,
Secure Hash Standard (SHS), FIPS PUB 180-4, 2012.
""")
if mibBuilder.loadTexts:
    usmHMAC192SHA256AuthProtocol.setDescription("""\
The Authentication Protocol usmHMAC192SHA256AuthProtocol uses HMAC-SHA-256 and
truncates output to 192 bits.
""")
_UsmHMAC256SHA384AuthProtocol_ObjectIdentity = ObjectIdentity
usmHMAC256SHA384AuthProtocol = _UsmHMAC256SHA384AuthProtocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 1, 6)
)
if mibBuilder.loadTexts:
    usmHMAC256SHA384AuthProtocol.setStatus("current")
if mibBuilder.loadTexts:
    usmHMAC256SHA384AuthProtocol.setReference("""\
- Krawczyk, H., Bellare, M., and R. Canetti, HMAC: Keyed-Hashing for Message
Authentication, RFC 2104. - National Institute of Standards and Technology,
Secure Hash Standard (SHS), FIPS PUB 180-4, 2012.
""")
if mibBuilder.loadTexts:
    usmHMAC256SHA384AuthProtocol.setDescription("""\
The Authentication Protocol usmHMAC256SHA384AuthProtocol uses HMAC-SHA-384 and
truncates output to 256 bits.
""")
_UsmHMAC384SHA512AuthProtocol_ObjectIdentity = ObjectIdentity
usmHMAC384SHA512AuthProtocol = _UsmHMAC384SHA512AuthProtocol_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 10, 1, 1, 7)
)
if mibBuilder.loadTexts:
    usmHMAC384SHA512AuthProtocol.setStatus("current")
if mibBuilder.loadTexts:
    usmHMAC384SHA512AuthProtocol.setReference("""\
- Krawczyk, H., Bellare, M., and R. Canetti, HMAC: Keyed-Hashing for Message
Authentication, RFC 2104. - National Institute of Standards and Technology,
Secure Hash Standard (SHS), FIPS PUB 180-4, 2012.
""")
if mibBuilder.loadTexts:
    usmHMAC384SHA512AuthProtocol.setDescription("""\
The Authentication Protocol usmHMAC384SHA512AuthProtocol uses HMAC-SHA-512 and
truncates output to 384 bits.
""")

mibBuilder.exportSymbols(
    "SNMP-USM-HMAC-SHA2-MIB",
    **{"snmpUsmHmacSha2MIB": snmpUsmHmacSha2MIB,
       "usmHMAC128SHA224AuthProtocol": usmHMAC128SHA224AuthProtocol,
       "usmHMAC192SHA256AuthProtocol": usmHMAC192SHA256AuthProtocol,
       "usmHMAC256SHA384AuthProtocol": usmHMAC256SHA384AuthProtocol,
       "usmHMAC384SHA512AuthProtocol": usmHMAC384SHA512AuthProtocol}
)
