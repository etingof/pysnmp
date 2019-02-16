#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# It is a stripped version of MIB that contains only symbols that is
# unique to SMIv1 and have no analogues in SMIv2
#
from pysnmp.proto.rfc1155 import NetworkAddress


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

(iso,
 mib_2,
 Counter32,
 Integer32,
 Unsigned32,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 NotificationType,
 Gauge32,
 ModuleIdentity,
 Counter64,
 ObjectIdentity,
 MibIdentifier,
 IpAddress,
 mgmt,
 TimeTicks,
 Bits) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "iso",
    "mib-2",
    "Counter32",
    "Integer32",
    "Unsigned32",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "NotificationType",
    "Gauge32",
    "ModuleIdentity",
    "Counter64",
    "ObjectIdentity",
    "MibIdentifier",
    "IpAddress",
    "mgmt",
    "TimeTicks",
    "Bits")

(PhysAddress,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "PhysAddress",
    "DisplayString")

_At_ObjectIdentity = ObjectIdentity
at = _At_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 3)
)
_AtTable_Object = MibTable
atTable = _AtTable_Object(
    (1, 3, 6, 1, 2, 1, 3, 1)
)
if mibBuilder.loadTexts:
    atTable.setStatus("deprecated")
if mibBuilder.loadTexts:
    atTable.setDescription("""\
The Address Translation tables contain the NetworkAddress to `physical' address
equivalences. Some interfaces do not use translation tables for determining
address equivalences (e.g., DDN-X.25 has an algorithmic method); if all
interfaces are of this type, then the Address Translation table is empty, i.e.,
has zero entries.
""")
_AtEntry_Object = MibTableRow
atEntry = _AtEntry_Object(
    (1, 3, 6, 1, 2, 1, 3, 1, 1)
)
atEntry.setIndexNames(
    (0, "RFC1213-MIB", "atIfIndex"),
    (0, "RFC1213-MIB", "atNetAddress"),
)
if mibBuilder.loadTexts:
    atEntry.setStatus("deprecated")
if mibBuilder.loadTexts:
    atEntry.setDescription("""\
Each entry contains one NetworkAddress to `physical' address equivalence.
""")
_AtIfIndex_Type = Integer32
_AtIfIndex_Object = MibTableColumn
atIfIndex = _AtIfIndex_Object(
    (1, 3, 6, 1, 2, 1, 3, 1, 1, 1),
    _AtIfIndex_Type()
)
atIfIndex.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    atIfIndex.setStatus("deprecated")
if mibBuilder.loadTexts:
    atIfIndex.setDescription("""\
The interface on which this entry's equivalence is effective. The interface
identified by a particular value of this index is the same interface as
identified by the same value of ifIndex.
""")
_AtPhysAddress_Type = PhysAddress
_AtPhysAddress_Object = MibTableColumn
atPhysAddress = _AtPhysAddress_Object(
    (1, 3, 6, 1, 2, 1, 3, 1, 1, 2),
    _AtPhysAddress_Type()
)
atPhysAddress.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    atPhysAddress.setStatus("deprecated")
if mibBuilder.loadTexts:
    atPhysAddress.setDescription("""\
The media-dependent `physical' address. Setting this object to a null string
(one of zero length) has the effect of invaliding the corresponding entry in
the atTable object. That is, it effectively dissasociates the interface
identified with said entry from the mapping identified with said entry. It is
an implementation-specific matter as to whether the agent removes an
invalidated entry from the table. Accordingly, management stations must be
prepared to receive tabular information from agents that corresponds to entries
not currently in use. Proper interpretation of such entries requires
examination of the relevant atPhysAddress object.
""")
_AtNetAddress_Type = NetworkAddress
_AtNetAddress_Object = MibTableColumn
atNetAddress = _AtNetAddress_Object(
    (1, 3, 6, 1, 2, 1, 3, 1, 1, 3),
    _AtNetAddress_Type()
)
atNetAddress.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    atNetAddress.setStatus("deprecated")
if mibBuilder.loadTexts:
    atNetAddress.setDescription("""\
The NetworkAddress (e.g., the IP address) corresponding to the media-dependent
`physical' address.
""")
_Ip_ObjectIdentity = ObjectIdentity
ip = _Ip_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 4)
)


class _IpForwarding_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("forwarding", 1),
          ("not-forwarding", 2))
    )


_IpForwarding_Type.__name__ = "Integer32"
_IpForwarding_Object = MibScalar
ipForwarding = _IpForwarding_Object(
    (1, 3, 6, 1, 2, 1, 4, 1),
    _IpForwarding_Type()
)
ipForwarding.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipForwarding.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipForwarding.setDescription("""\
The indication of whether this entity is acting as an IP gateway in respect to
the forwarding of datagrams received by, but not addressed to, this entity. IP
gateways forward datagrams. IP hosts do not (except those source-routed via the
host). Note that for some managed nodes, this object may take on only a subset
of the values possible. Accordingly, it is appropriate for an agent to return a
`badValue' response if a management station attempts to change this object to
an inappropriate value.
""")
_IpDefaultTTL_Type = Integer32
_IpDefaultTTL_Object = MibScalar
ipDefaultTTL = _IpDefaultTTL_Object(
    (1, 3, 6, 1, 2, 1, 4, 2),
    _IpDefaultTTL_Type()
)
ipDefaultTTL.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipDefaultTTL.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipDefaultTTL.setDescription("""\
The default value inserted into the Time-To-Live field of the IP header of
datagrams originated at this entity, whenever a TTL value is not supplied by
the transport layer protocol.
""")
_IpInReceives_Type = Counter32
_IpInReceives_Object = MibScalar
ipInReceives = _IpInReceives_Object(
    (1, 3, 6, 1, 2, 1, 4, 3),
    _IpInReceives_Type()
)
ipInReceives.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInReceives.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInReceives.setDescription("""\
The total number of input datagrams received from interfaces, including those
received in error.
""")
_IpInHdrErrors_Type = Counter32
_IpInHdrErrors_Object = MibScalar
ipInHdrErrors = _IpInHdrErrors_Object(
    (1, 3, 6, 1, 2, 1, 4, 4),
    _IpInHdrErrors_Type()
)
ipInHdrErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInHdrErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInHdrErrors.setDescription("""\
The number of input datagrams discarded due to errors in their IP headers,
including bad checksums, version number mismatch, other format errors, time-to-
live exceeded, errors discovered in processing their IP options, etc.
""")
_IpInAddrErrors_Type = Counter32
_IpInAddrErrors_Object = MibScalar
ipInAddrErrors = _IpInAddrErrors_Object(
    (1, 3, 6, 1, 2, 1, 4, 5),
    _IpInAddrErrors_Type()
)
ipInAddrErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInAddrErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInAddrErrors.setDescription("""\
The number of input datagrams discarded because the IP address in their IP
header's destination field was not a valid address to be received at this
entity. This count includes invalid addresses (e.g., 0.0.0.0) and addresses of
unsupported Classes (e.g., Class E). For entities which are not IP Gateways and
therefore do not forward datagrams, this counter includes datagrams discarded
because the destination address was not a local address.
""")
_IpForwDatagrams_Type = Counter32
_IpForwDatagrams_Object = MibScalar
ipForwDatagrams = _IpForwDatagrams_Object(
    (1, 3, 6, 1, 2, 1, 4, 6),
    _IpForwDatagrams_Type()
)
ipForwDatagrams.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipForwDatagrams.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipForwDatagrams.setDescription("""\
The number of input datagrams for which this entity was not their final IP
destination, as a result of which an attempt was made to find a route to
forward them to that final destination. In entities which do not act as IP
Gateways, this counter will include only those packets which were Source-Routed
via this entity, and the Source- Route option processing was successful.
""")
_IpInUnknownProtos_Type = Counter32
_IpInUnknownProtos_Object = MibScalar
ipInUnknownProtos = _IpInUnknownProtos_Object(
    (1, 3, 6, 1, 2, 1, 4, 7),
    _IpInUnknownProtos_Type()
)
ipInUnknownProtos.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInUnknownProtos.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInUnknownProtos.setDescription("""\
The number of locally-addressed datagrams received successfully but discarded
because of an unknown or unsupported protocol.
""")
_IpInDiscards_Type = Counter32
_IpInDiscards_Object = MibScalar
ipInDiscards = _IpInDiscards_Object(
    (1, 3, 6, 1, 2, 1, 4, 8),
    _IpInDiscards_Type()
)
ipInDiscards.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInDiscards.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInDiscards.setDescription("""\
The number of input IP datagrams for which no problems were encountered to
prevent their continued processing, but which were discarded (e.g., for lack of
buffer space). Note that this counter does not include any datagrams discarded
while awaiting re-assembly.
""")
_IpInDelivers_Type = Counter32
_IpInDelivers_Object = MibScalar
ipInDelivers = _IpInDelivers_Object(
    (1, 3, 6, 1, 2, 1, 4, 9),
    _IpInDelivers_Type()
)
ipInDelivers.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipInDelivers.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipInDelivers.setDescription("""\
The total number of input datagrams successfully delivered to IP user-protocols
(including ICMP).
""")
_IpOutRequests_Type = Counter32
_IpOutRequests_Object = MibScalar
ipOutRequests = _IpOutRequests_Object(
    (1, 3, 6, 1, 2, 1, 4, 10),
    _IpOutRequests_Type()
)
ipOutRequests.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipOutRequests.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipOutRequests.setDescription("""\
The total number of IP datagrams which local IP user-protocols (including ICMP)
supplied to IP in requests for transmission. Note that this counter does not
include any datagrams counted in ipForwDatagrams.
""")
_IpOutDiscards_Type = Counter32
_IpOutDiscards_Object = MibScalar
ipOutDiscards = _IpOutDiscards_Object(
    (1, 3, 6, 1, 2, 1, 4, 11),
    _IpOutDiscards_Type()
)
ipOutDiscards.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipOutDiscards.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipOutDiscards.setDescription("""\
The number of output IP datagrams for which no problem was encountered to
prevent their transmission to their destination, but which were discarded
(e.g., for lack of buffer space). Note that this counter would include
datagrams counted in ipForwDatagrams if any such packets met this
(discretionary) discard criterion.
""")
_IpOutNoRoutes_Type = Counter32
_IpOutNoRoutes_Object = MibScalar
ipOutNoRoutes = _IpOutNoRoutes_Object(
    (1, 3, 6, 1, 2, 1, 4, 12),
    _IpOutNoRoutes_Type()
)
ipOutNoRoutes.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipOutNoRoutes.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipOutNoRoutes.setDescription("""\
The number of IP datagrams discarded because no route could be found to
transmit them to their destination. Note that this counter includes any packets
counted in ipForwDatagrams which meet this `no-route' criterion. Note that this
includes any datagarms which a host cannot route because all of its default
gateways are down.
""")
_IpReasmTimeout_Type = Integer32
_IpReasmTimeout_Object = MibScalar
ipReasmTimeout = _IpReasmTimeout_Object(
    (1, 3, 6, 1, 2, 1, 4, 13),
    _IpReasmTimeout_Type()
)
ipReasmTimeout.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipReasmTimeout.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipReasmTimeout.setDescription("""\
The maximum number of seconds which received fragments are held while they are
awaiting reassembly at this entity.
""")
_IpReasmReqds_Type = Counter32
_IpReasmReqds_Object = MibScalar
ipReasmReqds = _IpReasmReqds_Object(
    (1, 3, 6, 1, 2, 1, 4, 14),
    _IpReasmReqds_Type()
)
ipReasmReqds.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipReasmReqds.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipReasmReqds.setDescription("""\
The number of IP fragments received which needed to be reassembled at this
entity.
""")
_IpReasmOKs_Type = Counter32
_IpReasmOKs_Object = MibScalar
ipReasmOKs = _IpReasmOKs_Object(
    (1, 3, 6, 1, 2, 1, 4, 15),
    _IpReasmOKs_Type()
)
ipReasmOKs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipReasmOKs.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipReasmOKs.setDescription("""\
The number of IP datagrams successfully re- assembled.
""")
_IpReasmFails_Type = Counter32
_IpReasmFails_Object = MibScalar
ipReasmFails = _IpReasmFails_Object(
    (1, 3, 6, 1, 2, 1, 4, 16),
    _IpReasmFails_Type()
)
ipReasmFails.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipReasmFails.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipReasmFails.setDescription("""\
The number of failures detected by the IP re- assembly algorithm (for whatever
reason: timed out, errors, etc). Note that this is not necessarily a count of
discarded IP fragments since some algorithms (notably the algorithm in RFC 815)
can lose track of the number of fragments by combining them as they are
received.
""")
_IpFragOKs_Type = Counter32
_IpFragOKs_Object = MibScalar
ipFragOKs = _IpFragOKs_Object(
    (1, 3, 6, 1, 2, 1, 4, 17),
    _IpFragOKs_Type()
)
ipFragOKs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipFragOKs.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipFragOKs.setDescription("""\
The number of IP datagrams that have been successfully fragmented at this
entity.
""")
_IpFragFails_Type = Counter32
_IpFragFails_Object = MibScalar
ipFragFails = _IpFragFails_Object(
    (1, 3, 6, 1, 2, 1, 4, 18),
    _IpFragFails_Type()
)
ipFragFails.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipFragFails.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipFragFails.setDescription("""\
The number of IP datagrams that have been discarded because they needed to be
fragmented at this entity but could not be, e.g., because their Don't Fragment
flag was set.
""")
_IpFragCreates_Type = Counter32
_IpFragCreates_Object = MibScalar
ipFragCreates = _IpFragCreates_Object(
    (1, 3, 6, 1, 2, 1, 4, 19),
    _IpFragCreates_Type()
)
ipFragCreates.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipFragCreates.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipFragCreates.setDescription("""\
The number of IP datagram fragments that have been generated as a result of
fragmentation at this entity.
""")
_IpAddrTable_Object = MibTable
ipAddrTable = _IpAddrTable_Object(
    (1, 3, 6, 1, 2, 1, 4, 20)
)
if mibBuilder.loadTexts:
    ipAddrTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAddrTable.setDescription("""\
The table of addressing information relevant to this entity's IP addresses.
""")
_IpAddrEntry_Object = MibTableRow
ipAddrEntry = _IpAddrEntry_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1)
)
ipAddrEntry.setIndexNames(
    (0, "RFC1213-MIB", "ipAdEntAddr"),
)
if mibBuilder.loadTexts:
    ipAddrEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAddrEntry.setDescription("""\
The addressing information for one of this entity's IP addresses.
""")
_IpAdEntAddr_Type = IpAddress
_IpAdEntAddr_Object = MibTableColumn
ipAdEntAddr = _IpAdEntAddr_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 1),
    _IpAdEntAddr_Type()
)
ipAdEntAddr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipAdEntAddr.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAdEntAddr.setDescription("""\
The IP address to which this entry's addressing information pertains.
""")
_IpAdEntIfIndex_Type = Integer32
_IpAdEntIfIndex_Object = MibTableColumn
ipAdEntIfIndex = _IpAdEntIfIndex_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 2),
    _IpAdEntIfIndex_Type()
)
ipAdEntIfIndex.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipAdEntIfIndex.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAdEntIfIndex.setDescription("""\
The index value which uniquely identifies the interface to which this entry is
applicable. The interface identified by a particular value of this index is the
same interface as identified by the same value of ifIndex.
""")
_IpAdEntNetMask_Type = IpAddress
_IpAdEntNetMask_Object = MibTableColumn
ipAdEntNetMask = _IpAdEntNetMask_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 3),
    _IpAdEntNetMask_Type()
)
ipAdEntNetMask.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipAdEntNetMask.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAdEntNetMask.setDescription("""\
The subnet mask associated with the IP address of this entry. The value of the
mask is an IP address with all the network bits set to 1 and all the hosts bits
set to 0.
""")
_IpAdEntBcastAddr_Type = Integer32
_IpAdEntBcastAddr_Object = MibTableColumn
ipAdEntBcastAddr = _IpAdEntBcastAddr_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 4),
    _IpAdEntBcastAddr_Type()
)
ipAdEntBcastAddr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipAdEntBcastAddr.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAdEntBcastAddr.setDescription("""\
The value of the least-significant bit in the IP broadcast address used for
sending datagrams on the (logical) interface associated with the IP address of
this entry. For example, when the Internet standard all-ones broadcast address
is used, the value will be 1. This value applies to both the subnet and network
broadcasts addresses used by the entity on this (logical) interface.
""")


class _IpAdEntReasmMaxSize_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )


_IpAdEntReasmMaxSize_Type.__name__ = "Integer32"
_IpAdEntReasmMaxSize_Object = MibTableColumn
ipAdEntReasmMaxSize = _IpAdEntReasmMaxSize_Object(
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 5),
    _IpAdEntReasmMaxSize_Type()
)
ipAdEntReasmMaxSize.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipAdEntReasmMaxSize.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipAdEntReasmMaxSize.setDescription("""\
The size of the largest IP datagram which this entity can re-assemble from
incoming IP fragmented datagrams received on this interface.
""")
_IpRouteTable_Object = MibTable
ipRouteTable = _IpRouteTable_Object(
    (1, 3, 6, 1, 2, 1, 4, 21)
)
if mibBuilder.loadTexts:
    ipRouteTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteTable.setDescription("""\
This entity's IP Routing table.
""")
_IpRouteEntry_Object = MibTableRow
ipRouteEntry = _IpRouteEntry_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1)
)
ipRouteEntry.setIndexNames(
    (0, "RFC1213-MIB", "ipRouteDest"),
)
if mibBuilder.loadTexts:
    ipRouteEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteEntry.setDescription("""\
A route to a particular destination.
""")
_IpRouteDest_Type = IpAddress
_IpRouteDest_Object = MibTableColumn
ipRouteDest = _IpRouteDest_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 1),
    _IpRouteDest_Type()
)
ipRouteDest.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteDest.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteDest.setDescription("""\
The destination IP address of this route. An entry with a value of 0.0.0.0 is
considered a default route. Multiple routes to a single destination can appear
in the table, but access to such multiple entries is dependent on the table-
access mechanisms defined by the network management protocol in use.
""")
_IpRouteIfIndex_Type = Integer32
_IpRouteIfIndex_Object = MibTableColumn
ipRouteIfIndex = _IpRouteIfIndex_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 2),
    _IpRouteIfIndex_Type()
)
ipRouteIfIndex.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteIfIndex.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteIfIndex.setDescription("""\
The index value which uniquely identifies the local interface through which the
next hop of this route should be reached. The interface identified by a
particular value of this index is the same interface as identified by the same
value of ifIndex.
""")
_IpRouteMetric1_Type = Integer32
_IpRouteMetric1_Object = MibTableColumn
ipRouteMetric1 = _IpRouteMetric1_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 3),
    _IpRouteMetric1_Type()
)
ipRouteMetric1.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMetric1.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMetric1.setDescription("""\
The primary routing metric for this route. The semantics of this metric are
determined by the routing-protocol specified in the route's ipRouteProto value.
If this metric is not used, its value should be set to -1.
""")
_IpRouteMetric2_Type = Integer32
_IpRouteMetric2_Object = MibTableColumn
ipRouteMetric2 = _IpRouteMetric2_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 4),
    _IpRouteMetric2_Type()
)
ipRouteMetric2.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMetric2.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMetric2.setDescription("""\
An alternate routing metric for this route. The semantics of this metric are
determined by the routing-protocol specified in the route's ipRouteProto value.
If this metric is not used, its value should be set to -1.
""")
_IpRouteMetric3_Type = Integer32
_IpRouteMetric3_Object = MibTableColumn
ipRouteMetric3 = _IpRouteMetric3_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 5),
    _IpRouteMetric3_Type()
)
ipRouteMetric3.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMetric3.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMetric3.setDescription("""\
An alternate routing metric for this route. The semantics of this metric are
determined by the routing-protocol specified in the route's ipRouteProto value.
If this metric is not used, its value should be set to -1.
""")
_IpRouteMetric4_Type = Integer32
_IpRouteMetric4_Object = MibTableColumn
ipRouteMetric4 = _IpRouteMetric4_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 6),
    _IpRouteMetric4_Type()
)
ipRouteMetric4.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMetric4.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMetric4.setDescription("""\
An alternate routing metric for this route. The semantics of this metric are
determined by the routing-protocol specified in the route's ipRouteProto value.
If this metric is not used, its value should be set to -1.
""")
_IpRouteNextHop_Type = IpAddress
_IpRouteNextHop_Object = MibTableColumn
ipRouteNextHop = _IpRouteNextHop_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 7),
    _IpRouteNextHop_Type()
)
ipRouteNextHop.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteNextHop.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteNextHop.setDescription("""\
The IP address of the next hop of this route. (In the case of a route bound to
an interface which is realized via a broadcast media, the value of this field
is the agent's IP address on that interface.)
""")


class _IpRouteType_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4)
        )
    )
    namedValues = NamedValues(
        *(("direct", 3),
          ("indirect", 4),
          ("invalid", 2),
          ("other", 1))
    )


_IpRouteType_Type.__name__ = "Integer32"
_IpRouteType_Object = MibTableColumn
ipRouteType = _IpRouteType_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 8),
    _IpRouteType_Type()
)
ipRouteType.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteType.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteType.setDescription("""\
The type of route. Note that the values direct(3) and indirect(4) refer to the
notion of direct and indirect routing in the IP architecture. Setting this
object to the value invalid(2) has the effect of invalidating the corresponding
entry in the ipRouteTable object. That is, it effectively dissasociates the
destination identified with said entry from the route identified with said
entry. It is an implementation-specific matter as to whether the agent removes
an invalidated entry from the table. Accordingly, management stations must be
prepared to receive tabular information from agents that corresponds to entries
not currently in use. Proper interpretation of such entries requires
examination of the relevant ipRouteType object.
""")


class _IpRouteProto_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4,
              5,
              6,
              7,
              8,
              9,
              10,
              11,
              12,
              13,
              14)
        )
    )
    namedValues = NamedValues(
        *(("bbnSpfIgp", 12),
          ("bgp", 14),
          ("ciscoIgrp", 11),
          ("egp", 5),
          ("es-is", 10),
          ("ggp", 6),
          ("hello", 7),
          ("icmp", 4),
          ("is-is", 9),
          ("local", 2),
          ("netmgmt", 3),
          ("ospf", 13),
          ("other", 1),
          ("rip", 8))
    )


_IpRouteProto_Type.__name__ = "Integer32"
_IpRouteProto_Object = MibTableColumn
ipRouteProto = _IpRouteProto_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 9),
    _IpRouteProto_Type()
)
ipRouteProto.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipRouteProto.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteProto.setDescription("""\
The routing mechanism via which this route was learned. Inclusion of values for
gateway routing protocols is not intended to imply that hosts should support
those protocols.
""")
_IpRouteAge_Type = Integer32
_IpRouteAge_Object = MibTableColumn
ipRouteAge = _IpRouteAge_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 10),
    _IpRouteAge_Type()
)
ipRouteAge.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteAge.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteAge.setDescription("""\
The number of seconds since this route was last updated or otherwise determined
to be correct. Note that no semantics of `too old' can be implied except
through knowledge of the routing protocol by which the route was learned.
""")
_IpRouteMask_Type = IpAddress
_IpRouteMask_Object = MibTableColumn
ipRouteMask = _IpRouteMask_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 11),
    _IpRouteMask_Type()
)
ipRouteMask.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMask.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMask.setDescription("""\
Indicate the mask to be logical-ANDed with the destination address before being
compared to the value in the ipRouteDest field. For those systems that do not
support arbitrary subnet masks, an agent constructs the value of the
ipRouteMask by determining whether the value of the correspondent ipRouteDest
field belong to a class-A, B, or C network, and then using one of: mask network
255.0.0.0 class-A 255.255.0.0 class-B 255.255.255.0 class-C If the value of the
ipRouteDest is 0.0.0.0 (a default route), then the mask value is also 0.0.0.0.
It should be noted that all IP routing subsystems implicitly use this
mechanism.
""")
_IpRouteMetric5_Type = Integer32
_IpRouteMetric5_Object = MibTableColumn
ipRouteMetric5 = _IpRouteMetric5_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 12),
    _IpRouteMetric5_Type()
)
ipRouteMetric5.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipRouteMetric5.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteMetric5.setDescription("""\
An alternate routing metric for this route. The semantics of this metric are
determined by the routing-protocol specified in the route's ipRouteProto value.
If this metric is not used, its value should be set to -1.
""")
_IpRouteInfo_Type = ObjectIdentifier
_IpRouteInfo_Object = MibTableColumn
ipRouteInfo = _IpRouteInfo_Object(
    (1, 3, 6, 1, 2, 1, 4, 21, 1, 13),
    _IpRouteInfo_Type()
)
ipRouteInfo.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipRouteInfo.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRouteInfo.setDescription("""\
A reference to MIB definitions specific to the particular routing protocol
which is responsible for this route, as determined by the value specified in
the route's ipRouteProto value. If this information is not present, its value
should be set to the OBJECT IDENTIFIER { 0 0 }, which is a syntatically valid
object identifier, and any conformant implementation of ASN.1 and BER must be
able to generate and recognize this value.
""")
_IpNetToMediaTable_Object = MibTable
ipNetToMediaTable = _IpNetToMediaTable_Object(
    (1, 3, 6, 1, 2, 1, 4, 22)
)
if mibBuilder.loadTexts:
    ipNetToMediaTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaTable.setDescription("""\
The IP Address Translation table used for mapping from IP addresses to physical
addresses.
""")
_IpNetToMediaEntry_Object = MibTableRow
ipNetToMediaEntry = _IpNetToMediaEntry_Object(
    (1, 3, 6, 1, 2, 1, 4, 22, 1)
)
ipNetToMediaEntry.setIndexNames(
    (0, "RFC1213-MIB", "ipNetToMediaIfIndex"),
    (0, "RFC1213-MIB", "ipNetToMediaNetAddress"),
)
if mibBuilder.loadTexts:
    ipNetToMediaEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaEntry.setDescription("""\
Each entry contains one IpAddress to `physical' address equivalence.
""")
_IpNetToMediaIfIndex_Type = Integer32
_IpNetToMediaIfIndex_Object = MibTableColumn
ipNetToMediaIfIndex = _IpNetToMediaIfIndex_Object(
    (1, 3, 6, 1, 2, 1, 4, 22, 1, 1),
    _IpNetToMediaIfIndex_Type()
)
ipNetToMediaIfIndex.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipNetToMediaIfIndex.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaIfIndex.setDescription("""\
The interface on which this entry's equivalence is effective. The interface
identified by a particular value of this index is the same interface as
identified by the same value of ifIndex.
""")
_IpNetToMediaPhysAddress_Type = PhysAddress
_IpNetToMediaPhysAddress_Object = MibTableColumn
ipNetToMediaPhysAddress = _IpNetToMediaPhysAddress_Object(
    (1, 3, 6, 1, 2, 1, 4, 22, 1, 2),
    _IpNetToMediaPhysAddress_Type()
)
ipNetToMediaPhysAddress.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipNetToMediaPhysAddress.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaPhysAddress.setDescription("""\
The media-dependent `physical' address.
""")
_IpNetToMediaNetAddress_Type = IpAddress
_IpNetToMediaNetAddress_Object = MibTableColumn
ipNetToMediaNetAddress = _IpNetToMediaNetAddress_Object(
    (1, 3, 6, 1, 2, 1, 4, 22, 1, 3),
    _IpNetToMediaNetAddress_Type()
)
ipNetToMediaNetAddress.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipNetToMediaNetAddress.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaNetAddress.setDescription("""\
The IpAddress corresponding to the media- dependent `physical' address.
""")


class _IpNetToMediaType_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4)
        )
    )
    namedValues = NamedValues(
        *(("dynamic", 3),
          ("invalid", 2),
          ("other", 1),
          ("static", 4))
    )


_IpNetToMediaType_Type.__name__ = "Integer32"
_IpNetToMediaType_Object = MibTableColumn
ipNetToMediaType = _IpNetToMediaType_Object(
    (1, 3, 6, 1, 2, 1, 4, 22, 1, 4),
    _IpNetToMediaType_Type()
)
ipNetToMediaType.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    ipNetToMediaType.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipNetToMediaType.setDescription("""\
The type of mapping. Setting this object to the value invalid(2) has the effect
of invalidating the corresponding entry in the ipNetToMediaTable. That is, it
effectively dissasociates the interface identified with said entry from the
mapping identified with said entry. It is an implementation-specific matter as
to whether the agent removes an invalidated entry from the table. Accordingly,
management stations must be prepared to receive tabular information from agents
that corresponds to entries not currently in use. Proper interpretation of such
entries requires examination of the relevant ipNetToMediaType object.
""")
_IpRoutingDiscards_Type = Counter32
_IpRoutingDiscards_Object = MibScalar
ipRoutingDiscards = _IpRoutingDiscards_Object(
    (1, 3, 6, 1, 2, 1, 4, 23),
    _IpRoutingDiscards_Type()
)
ipRoutingDiscards.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    ipRoutingDiscards.setStatus("mandatory")
if mibBuilder.loadTexts:
    ipRoutingDiscards.setDescription("""\
The number of routing entries which were chosen to be discarded even though
they are valid. One possible reason for discarding such an entry could be to
free-up buffer space for other routing entries.
""")
_Icmp_ObjectIdentity = ObjectIdentity
icmp = _Icmp_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 5)
)
_IcmpInMsgs_Type = Counter32
_IcmpInMsgs_Object = MibScalar
icmpInMsgs = _IcmpInMsgs_Object(
    (1, 3, 6, 1, 2, 1, 5, 1),
    _IcmpInMsgs_Type()
)
icmpInMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInMsgs.setDescription("""\
The total number of ICMP messages which the entity received. Note that this
counter includes all those counted by icmpInErrors.
""")
_IcmpInErrors_Type = Counter32
_IcmpInErrors_Object = MibScalar
icmpInErrors = _IcmpInErrors_Object(
    (1, 3, 6, 1, 2, 1, 5, 2),
    _IcmpInErrors_Type()
)
icmpInErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInErrors.setDescription("""\
The number of ICMP messages which the entity received but determined as having
ICMP-specific errors (bad ICMP checksums, bad length, etc.).
""")
_IcmpInDestUnreachs_Type = Counter32
_IcmpInDestUnreachs_Object = MibScalar
icmpInDestUnreachs = _IcmpInDestUnreachs_Object(
    (1, 3, 6, 1, 2, 1, 5, 3),
    _IcmpInDestUnreachs_Type()
)
icmpInDestUnreachs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInDestUnreachs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInDestUnreachs.setDescription("""\
The number of ICMP Destination Unreachable messages received.
""")
_IcmpInTimeExcds_Type = Counter32
_IcmpInTimeExcds_Object = MibScalar
icmpInTimeExcds = _IcmpInTimeExcds_Object(
    (1, 3, 6, 1, 2, 1, 5, 4),
    _IcmpInTimeExcds_Type()
)
icmpInTimeExcds.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInTimeExcds.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInTimeExcds.setDescription("""\
The number of ICMP Time Exceeded messages received.
""")
_IcmpInParmProbs_Type = Counter32
_IcmpInParmProbs_Object = MibScalar
icmpInParmProbs = _IcmpInParmProbs_Object(
    (1, 3, 6, 1, 2, 1, 5, 5),
    _IcmpInParmProbs_Type()
)
icmpInParmProbs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInParmProbs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInParmProbs.setDescription("""\
The number of ICMP Parameter Problem messages received.
""")
_IcmpInSrcQuenchs_Type = Counter32
_IcmpInSrcQuenchs_Object = MibScalar
icmpInSrcQuenchs = _IcmpInSrcQuenchs_Object(
    (1, 3, 6, 1, 2, 1, 5, 6),
    _IcmpInSrcQuenchs_Type()
)
icmpInSrcQuenchs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInSrcQuenchs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInSrcQuenchs.setDescription("""\
The number of ICMP Source Quench messages received.
""")
_IcmpInRedirects_Type = Counter32
_IcmpInRedirects_Object = MibScalar
icmpInRedirects = _IcmpInRedirects_Object(
    (1, 3, 6, 1, 2, 1, 5, 7),
    _IcmpInRedirects_Type()
)
icmpInRedirects.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInRedirects.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInRedirects.setDescription("""\
The number of ICMP Redirect messages received.
""")
_IcmpInEchos_Type = Counter32
_IcmpInEchos_Object = MibScalar
icmpInEchos = _IcmpInEchos_Object(
    (1, 3, 6, 1, 2, 1, 5, 8),
    _IcmpInEchos_Type()
)
icmpInEchos.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInEchos.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInEchos.setDescription("""\
The number of ICMP Echo (request) messages received.
""")
_IcmpInEchoReps_Type = Counter32
_IcmpInEchoReps_Object = MibScalar
icmpInEchoReps = _IcmpInEchoReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 9),
    _IcmpInEchoReps_Type()
)
icmpInEchoReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInEchoReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInEchoReps.setDescription("""\
The number of ICMP Echo Reply messages received.
""")
_IcmpInTimestamps_Type = Counter32
_IcmpInTimestamps_Object = MibScalar
icmpInTimestamps = _IcmpInTimestamps_Object(
    (1, 3, 6, 1, 2, 1, 5, 10),
    _IcmpInTimestamps_Type()
)
icmpInTimestamps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInTimestamps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInTimestamps.setDescription("""\
The number of ICMP Timestamp (request) messages received.
""")
_IcmpInTimestampReps_Type = Counter32
_IcmpInTimestampReps_Object = MibScalar
icmpInTimestampReps = _IcmpInTimestampReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 11),
    _IcmpInTimestampReps_Type()
)
icmpInTimestampReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInTimestampReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInTimestampReps.setDescription("""\
The number of ICMP Timestamp Reply messages received.
""")
_IcmpInAddrMasks_Type = Counter32
_IcmpInAddrMasks_Object = MibScalar
icmpInAddrMasks = _IcmpInAddrMasks_Object(
    (1, 3, 6, 1, 2, 1, 5, 12),
    _IcmpInAddrMasks_Type()
)
icmpInAddrMasks.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInAddrMasks.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInAddrMasks.setDescription("""\
The number of ICMP Address Mask Request messages received.
""")
_IcmpInAddrMaskReps_Type = Counter32
_IcmpInAddrMaskReps_Object = MibScalar
icmpInAddrMaskReps = _IcmpInAddrMaskReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 13),
    _IcmpInAddrMaskReps_Type()
)
icmpInAddrMaskReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpInAddrMaskReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpInAddrMaskReps.setDescription("""\
The number of ICMP Address Mask Reply messages received.
""")
_IcmpOutMsgs_Type = Counter32
_IcmpOutMsgs_Object = MibScalar
icmpOutMsgs = _IcmpOutMsgs_Object(
    (1, 3, 6, 1, 2, 1, 5, 14),
    _IcmpOutMsgs_Type()
)
icmpOutMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutMsgs.setDescription("""\
The total number of ICMP messages which this entity attempted to send. Note
that this counter includes all those counted by icmpOutErrors.
""")
_IcmpOutErrors_Type = Counter32
_IcmpOutErrors_Object = MibScalar
icmpOutErrors = _IcmpOutErrors_Object(
    (1, 3, 6, 1, 2, 1, 5, 15),
    _IcmpOutErrors_Type()
)
icmpOutErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutErrors.setDescription("""\
The number of ICMP messages which this entity did not send due to problems
discovered within ICMP such as a lack of buffers. This value should not include
errors discovered outside the ICMP layer such as the inability of IP to route
the resultant datagram. In some implementations there may be no types of error
which contribute to this counter's value.
""")
_IcmpOutDestUnreachs_Type = Counter32
_IcmpOutDestUnreachs_Object = MibScalar
icmpOutDestUnreachs = _IcmpOutDestUnreachs_Object(
    (1, 3, 6, 1, 2, 1, 5, 16),
    _IcmpOutDestUnreachs_Type()
)
icmpOutDestUnreachs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutDestUnreachs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutDestUnreachs.setDescription("""\
The number of ICMP Destination Unreachable messages sent.
""")
_IcmpOutTimeExcds_Type = Counter32
_IcmpOutTimeExcds_Object = MibScalar
icmpOutTimeExcds = _IcmpOutTimeExcds_Object(
    (1, 3, 6, 1, 2, 1, 5, 17),
    _IcmpOutTimeExcds_Type()
)
icmpOutTimeExcds.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutTimeExcds.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutTimeExcds.setDescription("""\
The number of ICMP Time Exceeded messages sent.
""")
_IcmpOutParmProbs_Type = Counter32
_IcmpOutParmProbs_Object = MibScalar
icmpOutParmProbs = _IcmpOutParmProbs_Object(
    (1, 3, 6, 1, 2, 1, 5, 18),
    _IcmpOutParmProbs_Type()
)
icmpOutParmProbs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutParmProbs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutParmProbs.setDescription("""\
The number of ICMP Parameter Problem messages sent.
""")
_IcmpOutSrcQuenchs_Type = Counter32
_IcmpOutSrcQuenchs_Object = MibScalar
icmpOutSrcQuenchs = _IcmpOutSrcQuenchs_Object(
    (1, 3, 6, 1, 2, 1, 5, 19),
    _IcmpOutSrcQuenchs_Type()
)
icmpOutSrcQuenchs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutSrcQuenchs.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutSrcQuenchs.setDescription("""\
The number of ICMP Source Quench messages sent.
""")
_IcmpOutRedirects_Type = Counter32
_IcmpOutRedirects_Object = MibScalar
icmpOutRedirects = _IcmpOutRedirects_Object(
    (1, 3, 6, 1, 2, 1, 5, 20),
    _IcmpOutRedirects_Type()
)
icmpOutRedirects.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutRedirects.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutRedirects.setDescription("""\
The number of ICMP Redirect messages sent. For a host, this object will always
be zero, since hosts do not send redirects.
""")
_IcmpOutEchos_Type = Counter32
_IcmpOutEchos_Object = MibScalar
icmpOutEchos = _IcmpOutEchos_Object(
    (1, 3, 6, 1, 2, 1, 5, 21),
    _IcmpOutEchos_Type()
)
icmpOutEchos.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutEchos.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutEchos.setDescription("""\
The number of ICMP Echo (request) messages sent.
""")
_IcmpOutEchoReps_Type = Counter32
_IcmpOutEchoReps_Object = MibScalar
icmpOutEchoReps = _IcmpOutEchoReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 22),
    _IcmpOutEchoReps_Type()
)
icmpOutEchoReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutEchoReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutEchoReps.setDescription("""\
The number of ICMP Echo Reply messages sent.
""")
_IcmpOutTimestamps_Type = Counter32
_IcmpOutTimestamps_Object = MibScalar
icmpOutTimestamps = _IcmpOutTimestamps_Object(
    (1, 3, 6, 1, 2, 1, 5, 23),
    _IcmpOutTimestamps_Type()
)
icmpOutTimestamps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutTimestamps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutTimestamps.setDescription("""\
The number of ICMP Timestamp (request) messages sent.
""")
_IcmpOutTimestampReps_Type = Counter32
_IcmpOutTimestampReps_Object = MibScalar
icmpOutTimestampReps = _IcmpOutTimestampReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 24),
    _IcmpOutTimestampReps_Type()
)
icmpOutTimestampReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutTimestampReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutTimestampReps.setDescription("""\
The number of ICMP Timestamp Reply messages sent.
""")
_IcmpOutAddrMasks_Type = Counter32
_IcmpOutAddrMasks_Object = MibScalar
icmpOutAddrMasks = _IcmpOutAddrMasks_Object(
    (1, 3, 6, 1, 2, 1, 5, 25),
    _IcmpOutAddrMasks_Type()
)
icmpOutAddrMasks.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutAddrMasks.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutAddrMasks.setDescription("""\
The number of ICMP Address Mask Request messages sent.
""")
_IcmpOutAddrMaskReps_Type = Counter32
_IcmpOutAddrMaskReps_Object = MibScalar
icmpOutAddrMaskReps = _IcmpOutAddrMaskReps_Object(
    (1, 3, 6, 1, 2, 1, 5, 26),
    _IcmpOutAddrMaskReps_Type()
)
icmpOutAddrMaskReps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    icmpOutAddrMaskReps.setStatus("mandatory")
if mibBuilder.loadTexts:
    icmpOutAddrMaskReps.setDescription("""\
The number of ICMP Address Mask Reply messages sent.
""")
_Tcp_ObjectIdentity = ObjectIdentity
tcp = _Tcp_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 6)
)


class _TcpRtoAlgorithm_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4)
        )
    )
    namedValues = NamedValues(
        *(("constant", 2),
          ("other", 1),
          ("rsre", 3),
          ("vanj", 4))
    )


_TcpRtoAlgorithm_Type.__name__ = "Integer32"
_TcpRtoAlgorithm_Object = MibScalar
tcpRtoAlgorithm = _TcpRtoAlgorithm_Object(
    (1, 3, 6, 1, 2, 1, 6, 1),
    _TcpRtoAlgorithm_Type()
)
tcpRtoAlgorithm.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpRtoAlgorithm.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpRtoAlgorithm.setDescription("""\
The algorithm used to determine the timeout value used for retransmitting
unacknowledged octets.
""")
_TcpRtoMin_Type = Integer32
_TcpRtoMin_Object = MibScalar
tcpRtoMin = _TcpRtoMin_Object(
    (1, 3, 6, 1, 2, 1, 6, 2),
    _TcpRtoMin_Type()
)
tcpRtoMin.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpRtoMin.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpRtoMin.setDescription("""\
The minimum value permitted by a TCP implementation for the retransmission
timeout, measured in milliseconds. More refined semantics for objects of this
type depend upon the algorithm used to determine the retransmission timeout. In
particular, when the timeout algorithm is rsre(3), an object of this type has
the semantics of the LBOUND quantity described in RFC 793.
""")
_TcpRtoMax_Type = Integer32
_TcpRtoMax_Object = MibScalar
tcpRtoMax = _TcpRtoMax_Object(
    (1, 3, 6, 1, 2, 1, 6, 3),
    _TcpRtoMax_Type()
)
tcpRtoMax.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpRtoMax.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpRtoMax.setDescription("""\
The maximum value permitted by a TCP implementation for the retransmission
timeout, measured in milliseconds. More refined semantics for objects of this
type depend upon the algorithm used to determine the retransmission timeout. In
particular, when the timeout algorithm is rsre(3), an object of this type has
the semantics of the UBOUND quantity described in RFC 793.
""")
_TcpMaxConn_Type = Integer32
_TcpMaxConn_Object = MibScalar
tcpMaxConn = _TcpMaxConn_Object(
    (1, 3, 6, 1, 2, 1, 6, 4),
    _TcpMaxConn_Type()
)
tcpMaxConn.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpMaxConn.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpMaxConn.setDescription("""\
The limit on the total number of TCP connections the entity can support. In
entities where the maximum number of connections is dynamic, this object should
contain the value -1.
""")
_TcpActiveOpens_Type = Counter32
_TcpActiveOpens_Object = MibScalar
tcpActiveOpens = _TcpActiveOpens_Object(
    (1, 3, 6, 1, 2, 1, 6, 5),
    _TcpActiveOpens_Type()
)
tcpActiveOpens.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpActiveOpens.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpActiveOpens.setDescription("""\
The number of times TCP connections have made a direct transition to the SYN-
SENT state from the CLOSED state.
""")
_TcpPassiveOpens_Type = Counter32
_TcpPassiveOpens_Object = MibScalar
tcpPassiveOpens = _TcpPassiveOpens_Object(
    (1, 3, 6, 1, 2, 1, 6, 6),
    _TcpPassiveOpens_Type()
)
tcpPassiveOpens.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpPassiveOpens.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpPassiveOpens.setDescription("""\
The number of times TCP connections have made a direct transition to the SYN-
RCVD state from the LISTEN state.
""")
_TcpAttemptFails_Type = Counter32
_TcpAttemptFails_Object = MibScalar
tcpAttemptFails = _TcpAttemptFails_Object(
    (1, 3, 6, 1, 2, 1, 6, 7),
    _TcpAttemptFails_Type()
)
tcpAttemptFails.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpAttemptFails.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpAttemptFails.setDescription("""\
The number of times TCP connections have made a direct transition to the CLOSED
state from either the SYN-SENT state or the SYN-RCVD state, plus the number of
times TCP connections have made a direct transition to the LISTEN state from
the SYN-RCVD state.
""")
_TcpEstabResets_Type = Counter32
_TcpEstabResets_Object = MibScalar
tcpEstabResets = _TcpEstabResets_Object(
    (1, 3, 6, 1, 2, 1, 6, 8),
    _TcpEstabResets_Type()
)
tcpEstabResets.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpEstabResets.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpEstabResets.setDescription("""\
The number of times TCP connections have made a direct transition to the CLOSED
state from either the ESTABLISHED state or the CLOSE-WAIT state.
""")
_TcpCurrEstab_Type = Gauge32
_TcpCurrEstab_Object = MibScalar
tcpCurrEstab = _TcpCurrEstab_Object(
    (1, 3, 6, 1, 2, 1, 6, 9),
    _TcpCurrEstab_Type()
)
tcpCurrEstab.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpCurrEstab.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpCurrEstab.setDescription("""\
The number of TCP connections for which the current state is either ESTABLISHED
or CLOSE- WAIT.
""")
_TcpInSegs_Type = Counter32
_TcpInSegs_Object = MibScalar
tcpInSegs = _TcpInSegs_Object(
    (1, 3, 6, 1, 2, 1, 6, 10),
    _TcpInSegs_Type()
)
tcpInSegs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpInSegs.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpInSegs.setDescription("""\
The total number of segments received, including those received in error. This
count includes segments received on currently established connections.
""")
_TcpOutSegs_Type = Counter32
_TcpOutSegs_Object = MibScalar
tcpOutSegs = _TcpOutSegs_Object(
    (1, 3, 6, 1, 2, 1, 6, 11),
    _TcpOutSegs_Type()
)
tcpOutSegs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpOutSegs.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpOutSegs.setDescription("""\
The total number of segments sent, including those on current connections but
excluding those containing only retransmitted octets.
""")
_TcpRetransSegs_Type = Counter32
_TcpRetransSegs_Object = MibScalar
tcpRetransSegs = _TcpRetransSegs_Object(
    (1, 3, 6, 1, 2, 1, 6, 12),
    _TcpRetransSegs_Type()
)
tcpRetransSegs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpRetransSegs.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpRetransSegs.setDescription("""\
The total number of segments retransmitted - that is, the number of TCP
segments transmitted containing one or more previously transmitted octets.
""")
_TcpConnTable_Object = MibTable
tcpConnTable = _TcpConnTable_Object(
    (1, 3, 6, 1, 2, 1, 6, 13)
)
if mibBuilder.loadTexts:
    tcpConnTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnTable.setDescription("""\
A table containing TCP connection-specific information.
""")
_TcpConnEntry_Object = MibTableRow
tcpConnEntry = _TcpConnEntry_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1)
)
tcpConnEntry.setIndexNames(
    (0, "RFC1213-MIB", "tcpConnLocalAddress"),
    (0, "RFC1213-MIB", "tcpConnLocalPort"),
    (0, "RFC1213-MIB", "tcpConnRemAddress"),
    (0, "RFC1213-MIB", "tcpConnRemPort"),
)
if mibBuilder.loadTexts:
    tcpConnEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnEntry.setDescription("""\
Information about a particular current TCP connection. An object of this type
is transient, in that it ceases to exist when (or soon after) the connection
makes the transition to the CLOSED state.
""")


class _TcpConnState_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4,
              5,
              6,
              7,
              8,
              9,
              10,
              11,
              12)
        )
    )
    namedValues = NamedValues(
        *(("closeWait", 8),
          ("closed", 1),
          ("closing", 10),
          ("deleteTCB", 12),
          ("established", 5),
          ("finWait1", 6),
          ("finWait2", 7),
          ("lastAck", 9),
          ("listen", 2),
          ("synReceived", 4),
          ("synSent", 3),
          ("timeWait", 11))
    )


_TcpConnState_Type.__name__ = "Integer32"
_TcpConnState_Object = MibTableColumn
tcpConnState = _TcpConnState_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1, 1),
    _TcpConnState_Type()
)
tcpConnState.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    tcpConnState.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnState.setDescription("""\
The state of this TCP connection. The only value which may be set by a
management station is deleteTCB(12). Accordingly, it is appropriate for an
agent to return a `badValue' response if a management station attempts to set
this object to any other value. If a management station sets this object to the
value deleteTCB(12), then this has the effect of deleting the TCB (as defined
in RFC 793) of the corresponding connection on the managed node, resulting in
immediate termination of the connection. As an implementation-specific option,
a RST segment may be sent from the managed node to the other TCP endpoint (note
however that RST segments are not sent reliably).
""")
_TcpConnLocalAddress_Type = IpAddress
_TcpConnLocalAddress_Object = MibTableColumn
tcpConnLocalAddress = _TcpConnLocalAddress_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1, 2),
    _TcpConnLocalAddress_Type()
)
tcpConnLocalAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpConnLocalAddress.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnLocalAddress.setDescription("""\
The local IP address for this TCP connection. In the case of a connection in
the listen state which is willing to accept connections for any IP interface
associated with the node, the value 0.0.0.0 is used.
""")


class _TcpConnLocalPort_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )


_TcpConnLocalPort_Type.__name__ = "Integer32"
_TcpConnLocalPort_Object = MibTableColumn
tcpConnLocalPort = _TcpConnLocalPort_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1, 3),
    _TcpConnLocalPort_Type()
)
tcpConnLocalPort.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpConnLocalPort.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnLocalPort.setDescription("""\
The local port number for this TCP connection.
""")
_TcpConnRemAddress_Type = IpAddress
_TcpConnRemAddress_Object = MibTableColumn
tcpConnRemAddress = _TcpConnRemAddress_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1, 4),
    _TcpConnRemAddress_Type()
)
tcpConnRemAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpConnRemAddress.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnRemAddress.setDescription("""\
The remote IP address for this TCP connection.
""")


class _TcpConnRemPort_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )


_TcpConnRemPort_Type.__name__ = "Integer32"
_TcpConnRemPort_Object = MibTableColumn
tcpConnRemPort = _TcpConnRemPort_Object(
    (1, 3, 6, 1, 2, 1, 6, 13, 1, 5),
    _TcpConnRemPort_Type()
)
tcpConnRemPort.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpConnRemPort.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpConnRemPort.setDescription("""\
The remote port number for this TCP connection.
""")
_TcpInErrs_Type = Counter32
_TcpInErrs_Object = MibScalar
tcpInErrs = _TcpInErrs_Object(
    (1, 3, 6, 1, 2, 1, 6, 14),
    _TcpInErrs_Type()
)
tcpInErrs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpInErrs.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpInErrs.setDescription("""\
The total number of segments received in error (e.g., bad TCP checksums).
""")
_TcpOutRsts_Type = Counter32
_TcpOutRsts_Object = MibScalar
tcpOutRsts = _TcpOutRsts_Object(
    (1, 3, 6, 1, 2, 1, 6, 15),
    _TcpOutRsts_Type()
)
tcpOutRsts.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    tcpOutRsts.setStatus("mandatory")
if mibBuilder.loadTexts:
    tcpOutRsts.setDescription("""\
The number of TCP segments sent containing the RST flag.
""")
_Udp_ObjectIdentity = ObjectIdentity
udp = _Udp_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 7)
)
_UdpInDatagrams_Type = Counter32
_UdpInDatagrams_Object = MibScalar
udpInDatagrams = _UdpInDatagrams_Object(
    (1, 3, 6, 1, 2, 1, 7, 1),
    _UdpInDatagrams_Type()
)
udpInDatagrams.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpInDatagrams.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpInDatagrams.setDescription("""\
The total number of UDP datagrams delivered to UDP users.
""")
_UdpNoPorts_Type = Counter32
_UdpNoPorts_Object = MibScalar
udpNoPorts = _UdpNoPorts_Object(
    (1, 3, 6, 1, 2, 1, 7, 2),
    _UdpNoPorts_Type()
)
udpNoPorts.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpNoPorts.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpNoPorts.setDescription("""\
The total number of received UDP datagrams for which there was no application
at the destination port.
""")
_UdpInErrors_Type = Counter32
_UdpInErrors_Object = MibScalar
udpInErrors = _UdpInErrors_Object(
    (1, 3, 6, 1, 2, 1, 7, 3),
    _UdpInErrors_Type()
)
udpInErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpInErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpInErrors.setDescription("""\
The number of received UDP datagrams that could not be delivered for reasons
other than the lack of an application at the destination port.
""")
_UdpOutDatagrams_Type = Counter32
_UdpOutDatagrams_Object = MibScalar
udpOutDatagrams = _UdpOutDatagrams_Object(
    (1, 3, 6, 1, 2, 1, 7, 4),
    _UdpOutDatagrams_Type()
)
udpOutDatagrams.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpOutDatagrams.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpOutDatagrams.setDescription("""\
The total number of UDP datagrams sent from this entity.
""")
_UdpTable_Object = MibTable
udpTable = _UdpTable_Object(
    (1, 3, 6, 1, 2, 1, 7, 5)
)
if mibBuilder.loadTexts:
    udpTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpTable.setDescription("""\
A table containing UDP listener information.
""")
_UdpEntry_Object = MibTableRow
udpEntry = _UdpEntry_Object(
    (1, 3, 6, 1, 2, 1, 7, 5, 1)
)
udpEntry.setIndexNames(
    (0, "RFC1213-MIB", "udpLocalAddress"),
    (0, "RFC1213-MIB", "udpLocalPort"),
)
if mibBuilder.loadTexts:
    udpEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpEntry.setDescription("""\
Information about a particular current UDP listener.
""")
_UdpLocalAddress_Type = IpAddress
_UdpLocalAddress_Object = MibTableColumn
udpLocalAddress = _UdpLocalAddress_Object(
    (1, 3, 6, 1, 2, 1, 7, 5, 1, 1),
    _UdpLocalAddress_Type()
)
udpLocalAddress.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpLocalAddress.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpLocalAddress.setDescription("""\
The local IP address for this UDP listener. In the case of a UDP listener which
is willing to accept datagrams for any IP interface associated with the node,
the value 0.0.0.0 is used.
""")


class _UdpLocalPort_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueRangeConstraint(0, 65535),
    )


_UdpLocalPort_Type.__name__ = "Integer32"
_UdpLocalPort_Object = MibTableColumn
udpLocalPort = _UdpLocalPort_Object(
    (1, 3, 6, 1, 2, 1, 7, 5, 1, 2),
    _UdpLocalPort_Type()
)
udpLocalPort.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    udpLocalPort.setStatus("mandatory")
if mibBuilder.loadTexts:
    udpLocalPort.setDescription("""\
The local port number for this UDP listener.
""")
_Egp_ObjectIdentity = ObjectIdentity
egp = _Egp_ObjectIdentity(
    (1, 3, 6, 1, 2, 1, 8)
)
_EgpInMsgs_Type = Counter32
_EgpInMsgs_Object = MibScalar
egpInMsgs = _EgpInMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 1),
    _EgpInMsgs_Type()
)
egpInMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpInMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpInMsgs.setDescription("""\
The number of EGP messages received without error.
""")
_EgpInErrors_Type = Counter32
_EgpInErrors_Object = MibScalar
egpInErrors = _EgpInErrors_Object(
    (1, 3, 6, 1, 2, 1, 8, 2),
    _EgpInErrors_Type()
)
egpInErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpInErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpInErrors.setDescription("""\
The number of EGP messages received that proved to be in error.
""")
_EgpOutMsgs_Type = Counter32
_EgpOutMsgs_Object = MibScalar
egpOutMsgs = _EgpOutMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 3),
    _EgpOutMsgs_Type()
)
egpOutMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpOutMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpOutMsgs.setDescription("""\
The total number of locally generated EGP messages.
""")
_EgpOutErrors_Type = Counter32
_EgpOutErrors_Object = MibScalar
egpOutErrors = _EgpOutErrors_Object(
    (1, 3, 6, 1, 2, 1, 8, 4),
    _EgpOutErrors_Type()
)
egpOutErrors.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpOutErrors.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpOutErrors.setDescription("""\
The number of locally generated EGP messages not sent due to resource
limitations within an EGP entity.
""")
_EgpNeighTable_Object = MibTable
egpNeighTable = _EgpNeighTable_Object(
    (1, 3, 6, 1, 2, 1, 8, 5)
)
if mibBuilder.loadTexts:
    egpNeighTable.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighTable.setDescription("""\
The EGP neighbor table.
""")
_EgpNeighEntry_Object = MibTableRow
egpNeighEntry = _EgpNeighEntry_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1)
)
egpNeighEntry.setIndexNames(
    (0, "RFC1213-MIB", "egpNeighAddr"),
)
if mibBuilder.loadTexts:
    egpNeighEntry.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighEntry.setDescription("""\
Information about this entity's relationship with a particular EGP neighbor.
""")


class _EgpNeighState_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4,
              5)
        )
    )
    namedValues = NamedValues(
        *(("acquisition", 2),
          ("cease", 5),
          ("down", 3),
          ("idle", 1),
          ("up", 4))
    )


_EgpNeighState_Type.__name__ = "Integer32"
_EgpNeighState_Object = MibTableColumn
egpNeighState = _EgpNeighState_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 1),
    _EgpNeighState_Type()
)
egpNeighState.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighState.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighState.setDescription("""\
The EGP state of the local system with respect to this entry's EGP neighbor.
Each EGP state is represented by a value that is one greater than the numerical
value associated with said state in RFC 904.
""")
_EgpNeighAddr_Type = IpAddress
_EgpNeighAddr_Object = MibTableColumn
egpNeighAddr = _EgpNeighAddr_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 2),
    _EgpNeighAddr_Type()
)
egpNeighAddr.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighAddr.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighAddr.setDescription("""\
The IP address of this entry's EGP neighbor.
""")
_EgpNeighAs_Type = Integer32
_EgpNeighAs_Object = MibTableColumn
egpNeighAs = _EgpNeighAs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 3),
    _EgpNeighAs_Type()
)
egpNeighAs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighAs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighAs.setDescription("""\
The autonomous system of this EGP peer. Zero should be specified if the
autonomous system number of the neighbor is not yet known.
""")
_EgpNeighInMsgs_Type = Counter32
_EgpNeighInMsgs_Object = MibTableColumn
egpNeighInMsgs = _EgpNeighInMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 4),
    _EgpNeighInMsgs_Type()
)
egpNeighInMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighInMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighInMsgs.setDescription("""\
The number of EGP messages received without error from this EGP peer.
""")
_EgpNeighInErrs_Type = Counter32
_EgpNeighInErrs_Object = MibTableColumn
egpNeighInErrs = _EgpNeighInErrs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 5),
    _EgpNeighInErrs_Type()
)
egpNeighInErrs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighInErrs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighInErrs.setDescription("""\
The number of EGP messages received from this EGP peer that proved to be in
error (e.g., bad EGP checksum).
""")
_EgpNeighOutMsgs_Type = Counter32
_EgpNeighOutMsgs_Object = MibTableColumn
egpNeighOutMsgs = _EgpNeighOutMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 6),
    _EgpNeighOutMsgs_Type()
)
egpNeighOutMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighOutMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighOutMsgs.setDescription("""\
The number of locally generated EGP messages to this EGP peer.
""")
_EgpNeighOutErrs_Type = Counter32
_EgpNeighOutErrs_Object = MibTableColumn
egpNeighOutErrs = _EgpNeighOutErrs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 7),
    _EgpNeighOutErrs_Type()
)
egpNeighOutErrs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighOutErrs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighOutErrs.setDescription("""\
The number of locally generated EGP messages not sent to this EGP peer due to
resource limitations within an EGP entity.
""")
_EgpNeighInErrMsgs_Type = Counter32
_EgpNeighInErrMsgs_Object = MibTableColumn
egpNeighInErrMsgs = _EgpNeighInErrMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 8),
    _EgpNeighInErrMsgs_Type()
)
egpNeighInErrMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighInErrMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighInErrMsgs.setDescription("""\
The number of EGP-defined error messages received from this EGP peer.
""")
_EgpNeighOutErrMsgs_Type = Counter32
_EgpNeighOutErrMsgs_Object = MibTableColumn
egpNeighOutErrMsgs = _EgpNeighOutErrMsgs_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 9),
    _EgpNeighOutErrMsgs_Type()
)
egpNeighOutErrMsgs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighOutErrMsgs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighOutErrMsgs.setDescription("""\
The number of EGP-defined error messages sent to this EGP peer.
""")
_EgpNeighStateUps_Type = Counter32
_EgpNeighStateUps_Object = MibTableColumn
egpNeighStateUps = _EgpNeighStateUps_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 10),
    _EgpNeighStateUps_Type()
)
egpNeighStateUps.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighStateUps.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighStateUps.setDescription("""\
The number of EGP state transitions to the UP state with this EGP peer.
""")
_EgpNeighStateDowns_Type = Counter32
_EgpNeighStateDowns_Object = MibTableColumn
egpNeighStateDowns = _EgpNeighStateDowns_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 11),
    _EgpNeighStateDowns_Type()
)
egpNeighStateDowns.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighStateDowns.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighStateDowns.setDescription("""\
The number of EGP state transitions from the UP state to any other state with
this EGP peer.
""")
_EgpNeighIntervalHello_Type = Integer32
_EgpNeighIntervalHello_Object = MibTableColumn
egpNeighIntervalHello = _EgpNeighIntervalHello_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 12),
    _EgpNeighIntervalHello_Type()
)
egpNeighIntervalHello.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighIntervalHello.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighIntervalHello.setDescription("""\
The interval between EGP Hello command retransmissions (in hundredths of a
second). This represents the t1 timer as defined in RFC 904.
""")
_EgpNeighIntervalPoll_Type = Integer32
_EgpNeighIntervalPoll_Object = MibTableColumn
egpNeighIntervalPoll = _EgpNeighIntervalPoll_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 13),
    _EgpNeighIntervalPoll_Type()
)
egpNeighIntervalPoll.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighIntervalPoll.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighIntervalPoll.setDescription("""\
The interval between EGP poll command retransmissions (in hundredths of a
second). This represents the t3 timer as defined in RFC 904.
""")


class _EgpNeighMode_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("active", 1),
          ("passive", 2))
    )


_EgpNeighMode_Type.__name__ = "Integer32"
_EgpNeighMode_Object = MibTableColumn
egpNeighMode = _EgpNeighMode_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 14),
    _EgpNeighMode_Type()
)
egpNeighMode.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpNeighMode.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighMode.setDescription("""\
The polling mode of this EGP entity, either passive or active.
""")


class _EgpNeighEventTrigger_Type(Integer32):
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2)
        )
    )
    namedValues = NamedValues(
        *(("start", 1),
          ("stop", 2))
    )


_EgpNeighEventTrigger_Type.__name__ = "Integer32"
_EgpNeighEventTrigger_Object = MibTableColumn
egpNeighEventTrigger = _EgpNeighEventTrigger_Object(
    (1, 3, 6, 1, 2, 1, 8, 5, 1, 15),
    _EgpNeighEventTrigger_Type()
)
egpNeighEventTrigger.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    egpNeighEventTrigger.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpNeighEventTrigger.setDescription("""\
A control variable used to trigger operator- initiated Start and Stop events.
When read, this variable always returns the most recent value that
egpNeighEventTrigger was set to. If it has not been set since the last
initialization of the network management subsystem on the node, it returns a
value of `stop'. When set, this variable causes a Start or Stop event on the
specified neighbor, as specified on pages 8-10 of RFC 904. Briefly, a Start
event causes an Idle peer to begin neighbor acquisition and a non-Idle peer to
reinitiate neighbor acquisition. A stop event causes a non-Idle peer to return
to the Idle state until a Start event occurs, either via egpNeighEventTrigger
or otherwise.
""")
_EgpAs_Type = Integer32
_EgpAs_Object = MibScalar
egpAs = _EgpAs_Object(
    (1, 3, 6, 1, 2, 1, 8, 6),
    _EgpAs_Type()
)
egpAs.setMaxAccess("read-only")
if mibBuilder.loadTexts:
    egpAs.setStatus("mandatory")
if mibBuilder.loadTexts:
    egpAs.setDescription("""\
The autonomous system number of this EGP entity.
""")

mibBuilder.exportSymbols(
    "RFC1213-MIB",
    **{"mib_2": mib_2,
       "at": at,
       "atTable": atTable,
       "atEntry": atEntry,
       "atIfIndex": atIfIndex,
       "atPhysAddress": atPhysAddress,
       "atNetAddress": atNetAddress,
       "ip": ip,
       "ipForwarding": ipForwarding,
       "ipDefaultTTL": ipDefaultTTL,
       "ipInReceives": ipInReceives,
       "ipInHdrErrors": ipInHdrErrors,
       "ipInAddrErrors": ipInAddrErrors,
       "ipForwDatagrams": ipForwDatagrams,
       "ipInUnknownProtos": ipInUnknownProtos,
       "ipInDiscards": ipInDiscards,
       "ipInDelivers": ipInDelivers,
       "ipOutRequests": ipOutRequests,
       "ipOutDiscards": ipOutDiscards,
       "ipOutNoRoutes": ipOutNoRoutes,
       "ipReasmTimeout": ipReasmTimeout,
       "ipReasmReqds": ipReasmReqds,
       "ipReasmOKs": ipReasmOKs,
       "ipReasmFails": ipReasmFails,
       "ipFragOKs": ipFragOKs,
       "ipFragFails": ipFragFails,
       "ipFragCreates": ipFragCreates,
       "ipAddrTable": ipAddrTable,
       "ipAddrEntry": ipAddrEntry,
       "ipAdEntAddr": ipAdEntAddr,
       "ipAdEntIfIndex": ipAdEntIfIndex,
       "ipAdEntNetMask": ipAdEntNetMask,
       "ipAdEntBcastAddr": ipAdEntBcastAddr,
       "ipAdEntReasmMaxSize": ipAdEntReasmMaxSize,
       "ipRouteTable": ipRouteTable,
       "ipRouteEntry": ipRouteEntry,
       "ipRouteDest": ipRouteDest,
       "ipRouteIfIndex": ipRouteIfIndex,
       "ipRouteMetric1": ipRouteMetric1,
       "ipRouteMetric2": ipRouteMetric2,
       "ipRouteMetric3": ipRouteMetric3,
       "ipRouteMetric4": ipRouteMetric4,
       "ipRouteNextHop": ipRouteNextHop,
       "ipRouteType": ipRouteType,
       "ipRouteProto": ipRouteProto,
       "ipRouteAge": ipRouteAge,
       "ipRouteMask": ipRouteMask,
       "ipRouteMetric5": ipRouteMetric5,
       "ipRouteInfo": ipRouteInfo,
       "ipNetToMediaTable": ipNetToMediaTable,
       "ipNetToMediaEntry": ipNetToMediaEntry,
       "ipNetToMediaIfIndex": ipNetToMediaIfIndex,
       "ipNetToMediaPhysAddress": ipNetToMediaPhysAddress,
       "ipNetToMediaNetAddress": ipNetToMediaNetAddress,
       "ipNetToMediaType": ipNetToMediaType,
       "ipRoutingDiscards": ipRoutingDiscards,
       "icmp": icmp,
       "icmpInMsgs": icmpInMsgs,
       "icmpInErrors": icmpInErrors,
       "icmpInDestUnreachs": icmpInDestUnreachs,
       "icmpInTimeExcds": icmpInTimeExcds,
       "icmpInParmProbs": icmpInParmProbs,
       "icmpInSrcQuenchs": icmpInSrcQuenchs,
       "icmpInRedirects": icmpInRedirects,
       "icmpInEchos": icmpInEchos,
       "icmpInEchoReps": icmpInEchoReps,
       "icmpInTimestamps": icmpInTimestamps,
       "icmpInTimestampReps": icmpInTimestampReps,
       "icmpInAddrMasks": icmpInAddrMasks,
       "icmpInAddrMaskReps": icmpInAddrMaskReps,
       "icmpOutMsgs": icmpOutMsgs,
       "icmpOutErrors": icmpOutErrors,
       "icmpOutDestUnreachs": icmpOutDestUnreachs,
       "icmpOutTimeExcds": icmpOutTimeExcds,
       "icmpOutParmProbs": icmpOutParmProbs,
       "icmpOutSrcQuenchs": icmpOutSrcQuenchs,
       "icmpOutRedirects": icmpOutRedirects,
       "icmpOutEchos": icmpOutEchos,
       "icmpOutEchoReps": icmpOutEchoReps,
       "icmpOutTimestamps": icmpOutTimestamps,
       "icmpOutTimestampReps": icmpOutTimestampReps,
       "icmpOutAddrMasks": icmpOutAddrMasks,
       "icmpOutAddrMaskReps": icmpOutAddrMaskReps,
       "tcp": tcp,
       "tcpRtoAlgorithm": tcpRtoAlgorithm,
       "tcpRtoMin": tcpRtoMin,
       "tcpRtoMax": tcpRtoMax,
       "tcpMaxConn": tcpMaxConn,
       "tcpActiveOpens": tcpActiveOpens,
       "tcpPassiveOpens": tcpPassiveOpens,
       "tcpAttemptFails": tcpAttemptFails,
       "tcpEstabResets": tcpEstabResets,
       "tcpCurrEstab": tcpCurrEstab,
       "tcpInSegs": tcpInSegs,
       "tcpOutSegs": tcpOutSegs,
       "tcpRetransSegs": tcpRetransSegs,
       "tcpConnTable": tcpConnTable,
       "tcpConnEntry": tcpConnEntry,
       "tcpConnState": tcpConnState,
       "tcpConnLocalAddress": tcpConnLocalAddress,
       "tcpConnLocalPort": tcpConnLocalPort,
       "tcpConnRemAddress": tcpConnRemAddress,
       "tcpConnRemPort": tcpConnRemPort,
       "tcpInErrs": tcpInErrs,
       "tcpOutRsts": tcpOutRsts,
       "udp": udp,
       "udpInDatagrams": udpInDatagrams,
       "udpNoPorts": udpNoPorts,
       "udpInErrors": udpInErrors,
       "udpOutDatagrams": udpOutDatagrams,
       "udpTable": udpTable,
       "udpEntry": udpEntry,
       "udpLocalAddress": udpLocalAddress,
       "udpLocalPort": udpLocalPort,
       "egp": egp,
       "egpInMsgs": egpInMsgs,
       "egpInErrors": egpInErrors,
       "egpOutMsgs": egpOutMsgs,
       "egpOutErrors": egpOutErrors,
       "egpNeighTable": egpNeighTable,
       "egpNeighEntry": egpNeighEntry,
       "egpNeighState": egpNeighState,
       "egpNeighAddr": egpNeighAddr,
       "egpNeighAs": egpNeighAs,
       "egpNeighInMsgs": egpNeighInMsgs,
       "egpNeighInErrs": egpNeighInErrs,
       "egpNeighOutMsgs": egpNeighOutMsgs,
       "egpNeighOutErrs": egpNeighOutErrs,
       "egpNeighInErrMsgs": egpNeighInErrMsgs,
       "egpNeighOutErrMsgs": egpNeighOutErrMsgs,
       "egpNeighStateUps": egpNeighStateUps,
       "egpNeighStateDowns": egpNeighStateDowns,
       "egpNeighIntervalHello": egpNeighIntervalHello,
       "egpNeighIntervalPoll": egpNeighIntervalPoll,
       "egpNeighMode": egpNeighMode,
       "egpNeighEventTrigger": egpNeighEventTrigger,
       "egpAs": egpAs}
)
