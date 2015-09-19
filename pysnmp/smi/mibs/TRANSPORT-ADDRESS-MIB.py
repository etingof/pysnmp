#
# PySNMP MIB module TRANSPORT-ADDRESS-MIB (http://pysnmp.sf.net)
# ASN.1 source file:///usr/share/snmp/mibs/TRANSPORT-ADDRESS-MIB.txt
# Produced by pysmi-0.0.5 at Sat Sep 19 23:19:08 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, mib_2, IpAddress, TimeTicks, Counter64, Unsigned32, iso, Gauge32, ModuleIdentity, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "mib-2", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "iso", "Gauge32", "ModuleIdentity", "ObjectIdentity", "Bits", "Counter32")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")

#
# WARNING: some of the classes below are manually implemented
#
from pyasn1.compat.octets import int2oct, oct2int
from pysnmp import error
from pysnmp.carrier import sockfix
import socket

has_ipv6 = socket.has_ipv6

if hasattr(socket, 'inet_ntop') and hasattr(socket, 'inet_pton'):
    inet_ntop = socket.inet_ntop
    inet_pton = socket.inet_pton
else:
    import sys

    if sys.platform != "win32":
        from socket import inet_ntoa, inet_aton
        inet_ntop = lambda x,y: inet_ntoa(y)
        inet_pton = lambda x,y: inet_aton(y)
        has_ipv6 = False
    elif has_ipv6:
        import struct   # The case of old Python at old Windows 

        def inet_pton(address_family, ip_string):
            if address_family == socket.AF_INET:
                return inet_aton(ip_string)
            elif address_family != socket.AF_INET6:
                raise socket.error(
                          'Unknown address family %s' % (address_family,)
                      )

            groups = ip_string.split(":")
            spaces = groups.count('')

            if '.' in groups[-1]:
                groups[-1:] = [ "%x" % (x) for x in struct.unpack("!HH", inet_aton(groups[-1])) ]

            if spaces == 1:
                idx = groups.index('')
                groups[idx:idx+1] = ['0'] * (8 - len(groups) + 1)
            elif spaces == 2:
                zeros = ['0'] * (8 - len(groups) + 2)
                if ip_string.startswith('::'):
                    groups[:2] = zeros
                elif ip_string.endswith('::'):
                    groups[-2:] = zeros
                else:
                    raise socket.error(
                              'Invalid IPv6 address: "%s"' % (ip_string,)
                    )
            elif spaces == 3:
                if ip_string != '::':
                    raise socket.error(
                        'Invalid IPv6 address: "%s"' % (ip_string,)
                    )
                return '\x00' * 16
            elif spaces > 3:
                raise socket.error(
                          'Invalid IPv6 address: "%s"' % (ip_string,)
                )

            groups = [ t for t in [ int(t, 16) for t in groups ] if t & 0xFFFF == t ]

            if len(groups) != 8:
                raise socket.error(
                    'Invalid IPv6 address: "%s"' % (ip_string,)
                )

            return struct.pack('!8H', *groups)

        def inet_ntop(address_family, packed_ip):
            if address_family == socket.AF_INET:
                return inet_ntop(packed_ip)
            elif address_family != socket.AF_INET6:
                raise socket.error(
                    'Unknown address family %s' % (address_family,)
                )

            if len(packed_ip) != 16:
                raise socket.error(
                    'incorrect address length: %s' % len(packed_ip)
                )

            groups = list(struct.unpack('!8H', packed_ip))

            cur_base = best_base = cur_len = best_len = -1

            for idx in range(8):
                if groups[idx]:
                    if cur_base != -1:
                        if best_base == -1 or cur_len > best_len:
                            best_base, best_len = cur_base, cur_len
                        cur_base = -1
                else:
                    if cur_base == -1:
                        cur_base, cur_len = idx, 1
                    else:
                        cur_len += 1

            if cur_base != -1:
                if best_base == -1 or cur_len > best_len:
                    best_base, best_len = cur_base, cur_len

            if best_base != -1 and best_len > 1:
                groups[best_base:best_base + best_len] = [':']

            if groups[0] == ':':
                groups.insert(0, ':')
            if groups[-1] == ':':
                groups.append(':')

            f = lambda x: x != ':' and '%x' % x or ''

            return ':'.join([f(x) for x in groups])

transportAddressMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 100)).setRevisions(("2002-11-01 00:00",))
if mibBuilder.loadTexts: transportAddressMIB.setLastUpdated('200211010000Z')
if mibBuilder.loadTexts: transportAddressMIB.setOrganization('IETF Operations and Management Area')
if mibBuilder.loadTexts: transportAddressMIB.setContactInfo('Juergen Schoenwaelder (Editor)\n         TU Braunschweig\n         Bueltenweg 74/75\n         38106 Braunschweig, Germany\n\n         Phone: +49 531 391-3289\n         EMail: schoenw@ibr.cs.tu-bs.de\n\n         Send comments to <mibs@ops.ietf.org>.')
if mibBuilder.loadTexts: transportAddressMIB.setDescription('This MIB module provides commonly used transport\n         address definitions.\n\n         Copyright (C) The Internet Society (2002). This version of\n         this MIB module is part of RFC 3419; see the RFC itself for\n         full legal notices.')
transportDomains = MibIdentifier((1, 3, 6, 1, 2, 1, 100, 1))
transportDomainUdpIpv4 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 1))
if mibBuilder.loadTexts: transportDomainUdpIpv4.setDescription('The UDP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4 for\n         global IPv4 addresses.')
transportDomainUdpIpv6 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 2))
if mibBuilder.loadTexts: transportDomainUdpIpv6.setDescription('The UDP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6 for\n         global IPv6 addresses.')
transportDomainUdpIpv4z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 3))
if mibBuilder.loadTexts: transportDomainUdpIpv4z.setDescription('The UDP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4z for\n         scoped IPv4 addresses with a zone index.')
transportDomainUdpIpv6z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 4))
if mibBuilder.loadTexts: transportDomainUdpIpv6z.setDescription('The UDP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6z for\n         scoped IPv6 addresses with a zone index.')
transportDomainTcpIpv4 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 5))
if mibBuilder.loadTexts: transportDomainTcpIpv4.setDescription('The TCP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4 for\n         global IPv4 addresses.')
transportDomainTcpIpv6 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 6))
if mibBuilder.loadTexts: transportDomainTcpIpv6.setDescription('The TCP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6 for\n         global IPv6 addresses.')
transportDomainTcpIpv4z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 7))
if mibBuilder.loadTexts: transportDomainTcpIpv4z.setDescription('The TCP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4z for\n         scoped IPv4 addresses with a zone index.')
transportDomainTcpIpv6z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 8))
if mibBuilder.loadTexts: transportDomainTcpIpv6z.setDescription('The TCP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6z for\n         scoped IPv6 addresses with a zone index.')
transportDomainSctpIpv4 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 9))
if mibBuilder.loadTexts: transportDomainSctpIpv4.setDescription('The SCTP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4 for\n         global IPv4 addresses. This transport domain usually\n         represents the primary address on multihomed SCTP\n         endpoints.')
transportDomainSctpIpv6 = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 10))
if mibBuilder.loadTexts: transportDomainSctpIpv6.setDescription('The SCTP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6 for\n         global IPv6 addresses. This transport domain usually\n         represents the primary address on multihomed SCTP\n         endpoints.')
transportDomainSctpIpv4z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 11))
if mibBuilder.loadTexts: transportDomainSctpIpv4z.setDescription('The SCTP over IPv4 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv4z for\n         scoped IPv4 addresses with a zone index. This transport\n         domain usually represents the primary address on\n         multihomed SCTP endpoints.')
transportDomainSctpIpv6z = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 12))
if mibBuilder.loadTexts: transportDomainSctpIpv6z.setDescription('The SCTP over IPv6 transport domain.  The corresponding\n         transport address is of type TransportAddressIPv6z for\n         scoped IPv6 addresses with a zone index. This transport\n         domain usually represents the primary address on\n         multihomed SCTP endpoints.')
transportDomainLocal = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 13))
if mibBuilder.loadTexts: transportDomainLocal.setDescription('The Posix Local IPC transport domain. The corresponding\n         transport address is of type TransportAddressLocal.\n\n         The Posix Local IPC transport domain incorporates the\n         well-known UNIX domain sockets.')
transportDomainUdpDns = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 14))
if mibBuilder.loadTexts: transportDomainUdpDns.setDescription('The UDP transport domain using fully qualified domain\n         names. The corresponding transport address is of type\n         TransportAddressDns.')
transportDomainTcpDns = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 15))
if mibBuilder.loadTexts: transportDomainTcpDns.setDescription('The TCP transport domain using fully qualified domain\n         names. The corresponding transport address is of type\n         TransportAddressDns.')
transportDomainSctpDns = ObjectIdentity((1, 3, 6, 1, 2, 1, 100, 1, 16))
if mibBuilder.loadTexts: transportDomainSctpDns.setDescription('The SCTP transport domain using fully qualified domain\n         names. The corresponding transport address is of type\n         TransportAddressDns.')
class TransportDomain(ObjectIdentifier, TextualConvention):
    pass

class TransportAddressType(Integer32, TextualConvention):
    subtypeSpec = Integer32.subtypeSpec+SingleValueConstraint(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,)
    namedValues = NamedValues(("unknown", 0), ("udpIpv4", 1), ("udpIpv6", 2), ("udpIpv4z", 3), ("udpIpv6z", 4), ("tcpIpv4", 5), ("tcpIpv6", 6), ("tcpIpv4z", 7), ("tcpIpv6z", 8), ("sctpIpv4", 9), ("sctpIpv6", 10), ("sctpIpv4z", 11), ("sctpIpv6z", 12), ("local", 13), ("udpDns", 14), ("tcpDns", 15), ("sctpDns", 16),)

class TransportAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)

class TransportAddressIPv4(TextualConvention, OctetString):
    displayHint = "1d.1d.1d.1d:2d"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(6,6)
    fixedLength = 6
 
    def prettyIn(self, value):
        if isinstance(value, tuple):
            # Wild hack -- need to implement TextualConvention.prettyIn
            value = inet_pton(socket.AF_INET, value[0]) + \
                    int2oct((value[1] >> 8) & 0xff) + \
                    int2oct(value[1] & 0xff)
        return OctetString.prettyIn(self, value)

    # Socket address syntax coercion
    def __getitem__(self, i):
        if not hasattr(self, '__tuple_value'):
            v = self.asOctets()
            self.__tuple_value = (
                inet_ntop(socket.AF_INET, v[:4]),
                oct2int(v[4]) << 8 | oct2int(v[5]),
            )
        return self.__tuple_value[i]
    
class TransportAddressIPv6(TextualConvention, OctetString):
    displayHint = "0a[2x:2x:2x:2x:2x:2x:2x:2x]0a:2d"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(18,18)
    fixedLength = 18

    def prettyIn(self, value):
        if not has_ipv6:
            raise error.PySnmpError('IPv6 not supported by platform')
        if isinstance(value, tuple):
            value = inet_pton(socket.AF_INET6, value[0]) + \
                    int2oct((value[1] >> 8) & 0xff) + \
                    int2oct(value[1] & 0xff)
        return OctetString.prettyIn(self, value)

    # Socket address syntax coercion
    def __getitem__(self, i):
        if not hasattr(self, '__tuple_value'):
            if not has_ipv6:
                raise error.PySnmpError('IPv6 not supported by platform')
            v = self.asOctets()
            self.__tuple_value = (
                inet_ntop(socket.AF_INET6, v[:16]),
                oct2int(v[16]) << 8 | oct2int(v[17]),
                0,  # flowinfo
                0)  # scopeid
        return self.__tuple_value[i]

class TransportAddressIPv4z(OctetString, TextualConvention):
    displayHint = '1d.1d.1d.1d%4d:2d'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(10,10)
    fixedLength = 10

class TransportAddressIPv6z(OctetString, TextualConvention):
    displayHint = '0a[2x:2x:2x:2x:2x:2x:2x:2x%4d]0a:2d'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(22,22)
    fixedLength = 22

class TransportAddressLocal(OctetString, TextualConvention):
    displayHint = '1a'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(1,255)

class TransportAddressDns(OctetString, TextualConvention):
    displayHint = '1a'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(1,255)

mibBuilder.exportSymbols("TRANSPORT-ADDRESS-MIB", transportDomainTcpIpv4=transportDomainTcpIpv4, transportDomainTcpIpv6z=transportDomainTcpIpv6z, transportDomainLocal=transportDomainLocal, transportDomainSctpIpv4=transportDomainSctpIpv4, transportDomainTcpDns=transportDomainTcpDns, TransportAddressIPv6=TransportAddressIPv6, TransportAddressType=TransportAddressType, transportDomains=transportDomains, transportDomainUdpIpv6=transportDomainUdpIpv6, transportDomainUdpIpv6z=transportDomainUdpIpv6z, PYSNMP_MODULE_ID=transportAddressMIB, TransportAddressIPv4=TransportAddressIPv4, transportDomainSctpIpv6z=transportDomainSctpIpv6z, TransportDomain=TransportDomain, transportDomainUdpIpv4=transportDomainUdpIpv4, transportDomainTcpIpv4z=transportDomainTcpIpv4z, transportDomainSctpIpv4z=transportDomainSctpIpv4z, transportDomainSctpIpv6=transportDomainSctpIpv6, TransportAddressDns=TransportAddressDns, TransportAddress=TransportAddress, transportAddressMIB=transportAddressMIB, TransportAddressLocal=TransportAddressLocal, transportDomainUdpIpv4z=transportDomainUdpIpv4z, TransportAddressIPv6z=TransportAddressIPv6z, transportDomainTcpIpv6=transportDomainTcpIpv6, transportDomainUdpDns=transportDomainUdpDns, TransportAddressIPv4z=TransportAddressIPv4z, transportDomainSctpDns=transportDomainSctpDns)
