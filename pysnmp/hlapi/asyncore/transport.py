import socket, sys
from pysnmp.carrier.asynsock.dgram import udp, udp6, unix
from pysnmp import error
from pyasn1.compat.octets import null

class _AbstractTransportTarget:
    transportDomain = None
    protoTransport = NotImplementedError
    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        self.transportAddr = self._resolveAddr(transportAddr)
        self.timeout = timeout
        self.retries = retries
        self.tagList = tagList

    def __repr__(self): 
        return '%s(%r, timeout=%r, retries=%r, tagList=%r)' % (
            self.__class__.__name__, self.transportAddr,
            self.timeout, self.retries, self.tagList
        )

    def getTransportInfo(self):
        return self.transportDomain, self.transportAddr

    def openClientMode(self):
        self.transport = self.protoTransport().openClientMode()
        return self.transport

    def verifyDispatcherCompatibility(self, snmpEngine):
        if not self.protoTransport.isCompatibleWithDispatcher(snmpEngine.transportDispatcher):
            raise error.PySnmpError('Transport %r is not compatible with dispatcher %r' % (self.protoTransport, snmpEngine.transportDispatcher))

    def _resolveAddr(self, transportAddr): raise NotImplementedError()

class UdpTransportTarget(_AbstractTransportTarget):
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
