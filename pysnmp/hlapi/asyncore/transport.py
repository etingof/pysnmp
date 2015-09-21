import socket, sys
from pysnmp.carrier.asyncore.dgram import udp, udp6, unix
from pysnmp import error
from pyasn1.compat.octets import null

__all__ = ['UnixTransportTarget', 'Udp6TransportTarget', 'UdpTransportTarget']

class _AbstractTransportTarget:
    transportDomain = None
    protoTransport = NotImplementedError
    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        self.transportAddr = self._resolveAddr(transportAddr)
        self.timeout = timeout
        self.retries = retries
        self.tagList = tagList
        self.iface = None

    def __repr__(self): 
        return '%s(%r, timeout=%r, retries=%r, tagList=%r)' % (
            self.__class__.__name__, self.transportAddr,
            self.timeout, self.retries, self.tagList
        )

    def getTransportInfo(self):
        return self.transportDomain, self.transportAddr

    def setLocalAddress(self, iface):
        self.iface = iface
        return self

    def openClientMode(self):
        self.transport = self.protoTransport().openClientMode(self.iface)
        return self.transport

    def verifyDispatcherCompatibility(self, snmpEngine):
        if not self.protoTransport.isCompatibleWithDispatcher(snmpEngine.transportDispatcher):
            raise error.PySnmpError('Transport %r is not compatible with dispatcher %r' % (self.protoTransport, snmpEngine.transportDispatcher))

    def _resolveAddr(self, transportAddr): raise NotImplementedError()

class UdpTransportTarget(_AbstractTransportTarget):
    """Creates UDP/IPv4 configuration entry and initialize socket API if needed.

    This object can be used by 
    :py:class:`~pysnmp.hlapi.asyncore.AsyncCommandGenerator` or
    :py:class:`~pysnmp.hlapi.asyncore.AsyncNotificationOriginator`
    and their derevatives for adding new entries to Local Configuration
    Datastore (LCD) managed by :py:class:`~pysnmp.hlapi.SnmpEngine`
    class instance.

    See :RFC:`1906#section-3` for more information on the UDP transport mapping.

    Parameters
    ----------
    transportAddr : tuple
        Indicates remote address in Python :py:mod:`socket` module format
        which is a tuple of FQDN, port where FQDN is a string representing
        either hostname or IPv4 address in quad-dotted form, port is an
        integer.
    timeout : int
        Response timeout in seconds.
    retries : int
        Maximum number of request retries, 0 retries means just a single
        request.
    tagList : str
        Arbitrary string that contains a list of tag values which are used
        to select target addresses for a particular operation 
        (:RFC:`3413#section-4.1.4`).

    Examples
    --------
    >>> from pysnmp.hlapi.asyncore import UdpTransportTarget
    >>> UdpTransportTarget(('demo.snmplabs.com', 161))
    UdpTransportTarget(('195.218.195.228', 161), timeout=1, retries=5, tagList='')
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
        except socket.gaierror:
            raise error.PySnmpError('Bad IPv4/UDP transport address %s: %s' % ('@'.join([ str(x) for x in transportAddr ]), sys.exc_info()[1]))

class Udp6TransportTarget(_AbstractTransportTarget):
    """Creates UDP/IPv6 configuration entry and initialize socket API if needed.

    This object can be used by 
    :py:class:`~pysnmp.hlapi.asyncore.AsyncCommandGenerator` or
    :py:class:`~pysnmp.hlapi.asyncore.AsyncNotificationOriginator`
    and their derevatives for adding new entries to Local Configuration
    Datastore (LCD) managed by :py:class:`~pysnmp.hlapi.SnmpEngine`
    class instance.

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
    tagList : str
        Arbitrary string that contains a list of tag values which are used
        to select target addresses for a particular operation
        (:RFC:`3413#section-4.1.4`).

    Examples
    --------
    >>> from pysnmp.hlapi.asyncore import Udp6TransportTarget
    >>> Udp6TransportTarget(('google.com', 161))
    Udp6TransportTarget(('2a00:1450:4014:80a::100e', 161), timeout=1, retries=5, tagList='')
    >>> Udp6TransportTarget(('FEDC:BA98:7654:3210:FEDC:BA98:7654:3210', 161))
    Udp6TransportTarget(('fedc:ba98:7654:3210:fedc:ba98:7654:3210', 161), timeout=1, retries=5, tagList='')
    >>> Udp6TransportTarget(('1080:0:0:0:8:800:200C:417A', 161))
    Udp6TransportTarget(('1080::8:800:200c:417a', 161), timeout=1, retries=5, tagList='')
    >>> Udp6TransportTarget(('::0', 161))
    Udp6TransportTarget(('::', 161), timeout=1, retries=5, tagList='')
    >>> Udp6TransportTarget(('::', 161))
    Udp6TransportTarget(('::', 161), timeout=1, retries=5, tagList='')
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
        except socket.gaierror:
            raise error.PySnmpError('Bad IPv6/UDP transport address %s: %s' % ('@'.join([ str(x) for x in transportAddr ]), sys.exc_info()[1]))

class UnixTransportTarget(_AbstractTransportTarget):
    transportDomain = unix.domainName
    protoTransport = unix.UnixSocketTransport
