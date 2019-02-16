#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source file:///usr/share/snmp/mibs/INET-ADDRESS-MIB.txt
# Produced by pysmi-0.4.0 at Thu Feb 14 23:06:46 2019
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

(ModuleCompliance,
 NotificationGroup) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "ModuleCompliance",
    "NotificationGroup")

(TimeTicks,
 Gauge32,
 Integer32,
 Counter64,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 Bits,
 Counter32,
 ModuleIdentity,
 mib_2,
 Unsigned32,
 NotificationType,
 IpAddress,
 iso,
 MibIdentifier,
 ObjectIdentity) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "TimeTicks",
    "Gauge32",
    "Integer32",
    "Counter64",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "Bits",
    "Counter32",
    "ModuleIdentity",
    "mib-2",
    "Unsigned32",
    "NotificationType",
    "IpAddress",
    "iso",
    "MibIdentifier",
    "ObjectIdentity")

(TextualConvention,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString")

inetAddressMIB = ModuleIdentity(
    (1, 3, 6, 1, 2, 1, 76)
)
inetAddressMIB.setRevisions(
        ("2005-02-04 00:00",
         "2002-05-09 00:00",
         "2000-06-08 00:00")
)
inetAddressMIB.setLastUpdated("200502040000Z")
if mibBuilder.loadTexts:
    inetAddressMIB.setOrganization("""\
IETF Operations and Management Area
""")
inetAddressMIB.setContactInfo("""\
Juergen Schoenwaelder (Editor) International University Bremen P.O. Box 750 561
28725 Bremen, Germany Phone: +49 421 200-3587 EMail: j.schoenwaelder@iu-
bremen.de Send comments to <ietfmibs@ops.ietf.org>.
""")
if mibBuilder.loadTexts:
    inetAddressMIB.setDescription("""\
This MIB module defines textual conventions for representing Internet
addresses. An Internet address can be an IPv4 address, an IPv6 address, or a
DNS domain name. This module also defines textual conventions for Internet port
numbers, autonomous system numbers, and the length of an Internet address
prefix. Copyright (C) The Internet Society (2005). This version of this MIB
module is part of RFC 4001, see the RFC itself for full legal notices.
""")


class InetAddressType(TextualConvention, Integer32):
    status = "current"
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(0,
              1,
              2,
              3,
              4,
              16)
        )
    )
    namedValues = NamedValues(
        *(("dns", 16),
          ("ipv4", 1),
          ("ipv4z", 3),
          ("ipv6", 2),
          ("ipv6z", 4),
          ("unknown", 0))
    )

    if mibBuilder.loadTexts:
        description = """\
A value that represents a type of Internet address. unknown(0) An unknown
address type. This value MUST be used if the value of the corresponding
InetAddress object is a zero-length string. It may also be used to indicate an
IP address that is not in one of the formats defined below. ipv4(1) An IPv4
address as defined by the InetAddressIPv4 textual convention. ipv6(2) An IPv6
address as defined by the InetAddressIPv6 textual convention. ipv4z(3) A non-
global IPv4 address including a zone index as defined by the InetAddressIPv4z
textual convention. ipv6z(4) A non-global IPv6 address including a zone index
as defined by the InetAddressIPv6z textual convention. dns(16) A DNS domain
name as defined by the InetAddressDNS textual convention. Each definition of a
concrete InetAddressType value must be accompanied by a definition of a textual
convention for use with that InetAddressType. To support future extensions, the
InetAddressType textual convention SHOULD NOT be sub-typed in object type
definitions. It MAY be sub-typed in compliance statements in order to require
only a subset of these address types for a compliant implementation.
Implementations must ensure that InetAddressType objects and any dependent
objects (e.g., InetAddress objects) are consistent. An inconsistentValue error
must be generated if an attempt to change an InetAddressType object would, for
example, lead to an undefined InetAddress value. In particular,
InetAddressType/InetAddress pairs must be changed together if the address type
changes (e.g., from ipv6(2) to ipv4(1)).
"""


class InetAddressIPv4(TextualConvention, OctetString):
    status = "current"
    displayHint = "1d.1d.1d.1d"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(4, 4),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents an IPv4 network address: Octets Contents Encoding 1-4 IPv4 address
network-byte order The corresponding InetAddressType value is ipv4(1). This
textual convention SHOULD NOT be used directly in object definitions, as it
restricts addresses to a specific format. However, if it is used, it MAY be
used either on its own or in conjunction with InetAddressType, as a pair.
"""


class InetAddressIPv6(TextualConvention, OctetString):
    status = "current"
    displayHint = "2x:2x:2x:2x:2x:2x:2x:2x"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(16, 16),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents an IPv6 network address: Octets Contents Encoding 1-16 IPv6 address
network-byte order The corresponding InetAddressType value is ipv6(2). This
textual convention SHOULD NOT be used directly in object definitions, as it
restricts addresses to a specific format. However, if it is used, it MAY be
used either on its own or in conjunction with InetAddressType, as a pair.
"""


class InetAddressIPv4z(TextualConvention, OctetString):
    status = "current"
    displayHint = "1d.1d.1d.1d%4d"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 8),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents a non-global IPv4 network address, together with its zone index:
Octets Contents Encoding 1-4 IPv4 address network-byte order 5-8 zone index
network-byte order The corresponding InetAddressType value is ipv4z(3). The
zone index (bytes 5-8) is used to disambiguate identical address values on
nodes that have interfaces attached to different zones of the same scope. The
zone index may contain the special value 0, which refers to the default zone
for each scope. This textual convention SHOULD NOT be used directly in object
definitions, as it restricts addresses to a specific format. However, if it is
used, it MAY be used either on its own or in conjunction with InetAddressType,
as a pair.
"""


class InetAddressIPv6z(TextualConvention, OctetString):
    status = "current"
    displayHint = "2x:2x:2x:2x:2x:2x:2x:2x%4d"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(20, 20),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents a non-global IPv6 network address, together with its zone index:
Octets Contents Encoding 1-16 IPv6 address network-byte order 17-20 zone index
network-byte order The corresponding InetAddressType value is ipv6z(4). The
zone index (bytes 17-20) is used to disambiguate identical address values on
nodes that have interfaces attached to different zones of the same scope. The
zone index may contain the special value 0, which refers to the default zone
for each scope. This textual convention SHOULD NOT be used directly in object
definitions, as it restricts addresses to a specific format. However, if it is
used, it MAY be used either on its own or in conjunction with InetAddressType,
as a pair.
"""


class InetAddressDNS(TextualConvention, OctetString):
    status = "current"
    displayHint = "255a"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 255),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents a DNS domain name. The name SHOULD be fully qualified whenever
possible. The corresponding InetAddressType is dns(16). The DESCRIPTION clause
of InetAddress objects that may have InetAddressDNS values MUST fully describe
how (and when) these names are to be resolved to IP addresses. The resolution
of an InetAddressDNS value may require to query multiple DNS records (e.g., A
for IPv4 and AAAA for IPv6). The order of the resolution process and which DNS
record takes precedence depends on the configuration of the resolver. This
textual convention SHOULD NOT be used directly in object definitions, as it
restricts addresses to a specific format. However, if it is used, it MAY be
used either on its own or in conjunction with InetAddressType, as a pair.
"""


class InetAddress(TextualConvention, OctetString):
    status = "current"
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(0, 255),
    )

    if mibBuilder.loadTexts:
        description = """\
Denotes a generic Internet address. An InetAddress value is always interpreted
within the context of an InetAddressType value. Every usage of the InetAddress
textual convention is required to specify the InetAddressType object that
provides the context. It is suggested that the InetAddressType object be
logically registered before the object(s) that use the InetAddress textual
convention, if they appear in the same logical row. The value of an InetAddress
object must always be consistent with the value of the associated
InetAddressType object. Attempts to set an InetAddress object to a value
inconsistent with the associated InetAddressType must fail with an
inconsistentValue error. When this textual convention is used as the syntax of
an index object, there may be issues with the limit of 128 sub-identifiers
specified in SMIv2, STD 58. In this case, the object definition MUST include a
'SIZE' clause to limit the number of potential instance sub-identifiers;
otherwise the applicable constraints MUST be stated in the appropriate
conceptual row DESCRIPTION clauses, or in the surrounding documentation if
there is no single DESCRIPTION clause that is appropriate.
"""

    # https://tools.ietf.org/html/rfc4001#section-4.1

    TYPE_MAP = {
        InetAddressType.namedValues.getValue("ipv4"): InetAddressIPv4(),
        InetAddressType.namedValues.getValue("ipv6"): InetAddressIPv6(),
        InetAddressType.namedValues.getValue("ipv4z"): InetAddressIPv4z(),
        InetAddressType.namedValues.getValue("ipv6z"): InetAddressIPv6z(),
        InetAddressType.namedValues.getValue("dns"): InetAddressDNS()
    }

    @classmethod
    def cloneFromName(cls, value, impliedFlag, parentRow, parentIndices):
        for parentIndex in reversed(parentIndices):
            if isinstance(parentIndex, InetAddressType):
                try:
                    return parentRow.oidToValue(
                        cls.TYPE_MAP[int(parentIndex)], value, impliedFlag, parentIndices)

                except KeyError:
                    pass

        raise error.SmiError('%s object encountered without preceding '
                             'InetAddressType-like index: %r' % (cls.__name__, value))

    def cloneAsName(self, impliedFlag, parentRow, parentIndices):
        for parentIndex in reversed(parentIndices):
            if isinstance(parentIndex, InetAddressType):
                try:
                    return parentRow.valueToOid(
                        self.TYPE_MAP[int(parentIndex)].clone(
                            self.asOctets().decode('ascii')), impliedFlag, parentIndices)

                except KeyError:
                    pass

        raise error.SmiError('%s object encountered without preceding '
                             'InetAddressType-like index: %r' % (self.__class__.__name__, self))


class InetAddressPrefixLength(TextualConvention, Unsigned32):
    status = "current"
    displayHint = "d"
    subtypeSpec = Unsigned32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 2040),
    )

    if mibBuilder.loadTexts:
        description = """\
Denotes the length of a generic Internet network address prefix. A value of n
corresponds to an IP address mask that has n contiguous 1-bits from the most
significant bit (MSB), with all other bits set to 0. An InetAddressPrefixLength
value is always interpreted within the context of an InetAddressType value.
Every usage of the InetAddressPrefixLength textual convention is required to
specify the InetAddressType object that provides the context. It is suggested
that the InetAddressType object be logically registered before the object(s)
that use the InetAddressPrefixLength textual convention, if they appear in the
same logical row. InetAddressPrefixLength values larger than the maximum length
of an IP address for a specific InetAddressType are treated as the maximum
significant value applicable for the InetAddressType. The maximum significant
value is 32 for the InetAddressType 'ipv4(1)' and 'ipv4z(3)' and 128 for the
InetAddressType 'ipv6(2)' and 'ipv6z(4)'. The maximum significant value for the
InetAddressType 'dns(16)' is 0. The value zero is object-specific and must be
defined as part of the description of any object that uses this syntax.
Examples of the usage of zero might include situations where the Internet
network address prefix is unknown or does not apply. The upper bound of the
prefix length has been chosen to be consistent with the maximum size of an
InetAddress.
"""


class InetPortNumber(TextualConvention, Unsigned32):
    status = "current"
    displayHint = "d"
    subtypeSpec = Unsigned32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )

    if mibBuilder.loadTexts:
        description = """\
Represents a 16 bit port number of an Internet transport layer protocol. Port
numbers are assigned by IANA. A current list of all assignments is available
from <http://www.iana.org/>. The value zero is object-specific and must be
defined as part of the description of any object that uses this syntax.
Examples of the usage of zero might include situations where a port number is
unknown, or when the value zero is used as a wildcard in a filter.
"""


class InetAutonomousSystemNumber(TextualConvention, Unsigned32):
    status = "current"
    displayHint = "d"
    if mibBuilder.loadTexts:
        description = """\
Represents an autonomous system number that identifies an Autonomous System
(AS). An AS is a set of routers under a single technical administration, using
an interior gateway protocol and common metrics to route packets within the AS,
and using an exterior gateway protocol to route packets to other ASes'. IANA
maintains the AS number space and has delegated large parts to the regional
registries. Autonomous system numbers are currently limited to 16 bits
(0..65535). There is, however, work in progress to enlarge the autonomous
system number space to 32 bits. Therefore, this textual convention uses an
Unsigned32 value without a range restriction in order to support a larger
autonomous system number space.
"""


class InetScopeType(TextualConvention, Integer32):
    status = "current"
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4,
              5,
              8,
              14)
        )
    )
    namedValues = NamedValues(
        *(("adminLocal", 4),
          ("global", 14),
          ("interfaceLocal", 1),
          ("linkLocal", 2),
          ("organizationLocal", 8),
          ("siteLocal", 5),
          ("subnetLocal", 3))
    )

    if mibBuilder.loadTexts:
        description = """\
Represents a scope type. This textual convention can be used in cases where a
MIB has to represent different scope types and there is no context information,
such as an InetAddress object, that implicitly defines the scope type. Note
that not all possible values have been assigned yet, but they may be assigned
in future revisions of this specification. Applications should therefore be
able to deal with values not yet assigned.
"""


class InetZoneIndex(TextualConvention, Unsigned32):
    status = "current"
    displayHint = "d"
    if mibBuilder.loadTexts:
        description = """\
A zone index identifies an instance of a zone of a specific scope. The zone
index MUST disambiguate identical address values. For link-local addresses, the
zone index will typically be the interface index (ifIndex as defined in the IF-
MIB) of the interface on which the address is configured. The zone index may
contain the special value 0, which refers to the default zone. The default zone
may be used in cases where the valid zone index is not known (e.g., when a
management application has to write a link-local IPv6 address without knowing
the interface index value). The default zone SHOULD NOT be used as an easy way
out in cases where the zone index for a non-global IPv6 address is known.
"""


class InetVersion(TextualConvention, Integer32):
    status = "current"
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(0,
              1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("ipv4", 1),
          ("ipv6", 2),
          ("unknown", 0))
    )

    if mibBuilder.loadTexts:
        description = """\
A value representing a version of the IP protocol. unknown(0) An unknown or
unspecified version of the IP protocol. ipv4(1) The IPv4 protocol as defined in
RFC 791 (STD 5). ipv6(2) The IPv6 protocol as defined in RFC 2460. Note that
this textual convention SHOULD NOT be used to distinguish different address
types associated with IP protocols. The InetAddressType has been designed for
this purpose.
"""

mibBuilder.exportSymbols(
    "INET-ADDRESS-MIB",
    **{"InetAddressType": InetAddressType,
       "InetAddress": InetAddress,
       "InetAddressIPv4": InetAddressIPv4,
       "InetAddressIPv6": InetAddressIPv6,
       "InetAddressIPv4z": InetAddressIPv4z,
       "InetAddressIPv6z": InetAddressIPv6z,
       "InetAddressDNS": InetAddressDNS,
       "InetAddressPrefixLength": InetAddressPrefixLength,
       "InetPortNumber": InetPortNumber,
       "InetAutonomousSystemNumber": InetAutonomousSystemNumber,
       "InetScopeType": InetScopeType,
       "InetZoneIndex": InetZoneIndex,
       "InetVersion": InetVersion,
       "inetAddressMIB": inetAddressMIB}
)
