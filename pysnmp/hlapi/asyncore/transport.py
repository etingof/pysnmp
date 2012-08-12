import socket, sys
from pysnmp.carrier.asynsock.dgram import udp, udp6, unix
from pyasn1.compat.octets import null

class _AbstractTransportTarget:
    transportDomain = protoTransport = None
    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        self.transportAddr = transportAddr
        self.timeout = timeout
        self.retries = retries
        self.tagList = tagList

    def __repr__(self): return '%s(%r, %r, %r, %r)' % (
        self.__class__.__name__, self.transportAddr,
        self.timeout, self.retries, self.tagList
        )

    def __hash__(self): return hash(self.transportAddr)
    
    def __eq__(self, other): return self.transportAddr == other
    def __ne__(self, other): return self.transportAddr != other
    def __lt__(self, other): return self.transportAddr < other
    def __le__(self, other): return self.transportAddr <= other
    def __gt__(self, other): return self.transportAddr > other
    def __ge__(self, other): return self.transportAddr >= other
    
    def openClientMode(self):
        self.transport = self.protoTransport().openClientMode()
        return self.transport
 
class UdpTransportTarget(_AbstractTransportTarget):
    transportDomain = udp.domainName
    protoTransport = udp.UdpSocketTransport
    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        _AbstractTransportTarget.__init__(self, transportAddr, timeout,
                                          retries, tagList)
        try:
            self.transportAddr = socket.getaddrinfo(transportAddr[0],
                                                    transportAddr[1],
                                                    socket.AF_INET,
                                                    socket.SOCK_DGRAM,
                                                    socket.IPPROTO_UDP)[0][4][:2]
        except socket.gaierror:
            raise error.PySnmpError('Bad IPv4/UDP transport address %s: %s' % ('@'.join([ str(x) for x in transportAddr ]), sys.exc_info()[1]))

class Udp6TransportTarget(_AbstractTransportTarget):
    transportDomain = udp6.domainName
    protoTransport = udp6.Udp6SocketTransport
    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        _AbstractTransportTarget.__init__(self, transportAddr, timeout,
                                          retries, tagList)
        try:
            self.transportAddr = socket.getaddrinfo(transportAddr[0],
                                                    transportAddr[1],
                                                    socket.AF_INET6,
                                                    socket.SOCK_DGRAM,
                                                    socket.IPPROTO_UDP)[0][4][:2]
        except socket.gaierror:
            raise error.PySnmpError('Bad IPv6/UDP transport address %s: %s' % ('@'.join([ str(x) for x in transportAddr ]), sys.exc_info()[1]))

class UnixTransportTarget(_AbstractTransportTarget):
    transportDomain = unix.domainName
    protoTransport = unix.UnixSocketTransport


