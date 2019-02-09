#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import socket
import sys

from pysnmp import error
from pysnmp.carrier.asyncore.dgram import udp, udp6
from pysnmp.hlapi.transport import AbstractTransportTarget

__all__ = ['Udp6TransportTarget', 'UdpTransportTarget']


class UdpTransportTarget(AbstractTransportTarget):
    """Represent UDP/IPv4 transport endpoint.

    This object can be used for passing UDP/IPv4 configuration information
    to the low-level SNMP applications.

    See :RFC:`1906#section-3` for more information on the UDP transport mapping.

    Parameters
    ----------
    transportAddr: :py:class:`tuple`
        Indicates remote address in Python :py:mod:`socket` module format
        which is a tuple of FQDN, port where FQDN is a string representing
        either hostname or IPv4 address in quad-dotted form, port is an
        integer.
    timeout: :py:class:`int`
        Response timeout in seconds.
    retries: :py:class:`int`
        Maximum number of request retries, 0 retries means just a single
        request.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import UdpTransportTarget
    >>> UdpTransportTarget(('demo.snmplabs.com', 161))
    UdpTransportTarget(('195.218.195.228', 161), timeout=1, retries=5)
    >>>

    """
    transportDomain = udp.domainName
    protoTransport = udp.UdpSocketTransport

    def _resolveAddr(self, transportAddr):
        try:
            return socket.getaddrinfo(transportAddr[0],
                                      transportAddr[1],
                                      socket.AF_INET,
                                      socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP)[0][4][:2]
        except socket.gaierror as exc:
            raise error.PySnmpError('Bad IPv4/UDP transport address %s: %s' % (
                '@'.join([str(x) for x in transportAddr]), exc))


class Udp6TransportTarget(AbstractTransportTarget):
    """Represent UDP/IPv6 transport endpoint.

    This object can be used for passing UDP/IPv4 configuration information
    to the low-level SNMP applications.

    See :RFC:`1906#section-3`, :RFC:`2851#section-4` for more information
    on the UDP and IPv6 transport mapping.

    Parameters
    ----------
    transportAddr : tuple
        Indicates remote address in Python :py:mod:`socket` module format
        which is a tuple of FQDN, port where FQDN is a string representing
        either hostname or IPv6 address in one of three conventional forms
        (:RFC:`1924#section-3`), port is an integer.
    timeout : int
        Response timeout in seconds.
    retries : int
        Maximum number of request retries, 0 retries means just a single
        request.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import Udp6TransportTarget
    >>> Udp6TransportTarget(('google.com', 161))
    Udp6TransportTarget(('2a00:1450:4014:80a::100e', 161), timeout=1, retries=5)
    >>> Udp6TransportTarget(('FEDC:BA98:7654:3210:FEDC:BA98:7654:3210', 161))
    Udp6TransportTarget(('fedc:ba98:7654:3210:fedc:ba98:7654:3210', 161), timeout=1, retries=5)
    >>> Udp6TransportTarget(('1080:0:0:0:8:800:200C:417A', 161))
    Udp6TransportTarget(('1080::8:800:200c:417a', 161), timeout=1, retries=5)
    >>> Udp6TransportTarget(('::0', 161))
    Udp6TransportTarget(('::', 161), timeout=1, retries=5)
    >>> Udp6TransportTarget(('::', 161))
    Udp6TransportTarget(('::', 161), timeout=1, retries=5)
    >>>

    """
    transportDomain = udp6.domainName
    protoTransport = udp6.Udp6SocketTransport

    def _resolveAddr(self, transportAddr):
        try:
            return socket.getaddrinfo(transportAddr[0],
                                      transportAddr[1],
                                      socket.AF_INET6,
                                      socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP)[0][4][:2]
        except socket.gaierror as exc:
            raise error.PySnmpError('Bad IPv6/UDP transport address %s: %s' % (
                '@'.join([str(x) for x in transportAddr]), exc))
