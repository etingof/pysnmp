# Implements asyncore-based UDP transport domain
from socket import AF_INET
from pysnmp.carrier.base import AbstractTransportAddress
from pysnmp.carrier.asyncore.dgram.base import DgramSocketTransport

domainName = snmpUDPDomain = (1, 3, 6, 1, 6, 1, 1)

class UdpTransportAddress(tuple, AbstractTransportAddress): pass

class UdpSocketTransport(DgramSocketTransport):
    sockFamily = AF_INET
    addressType = UdpTransportAddress

UdpTransport = UdpSocketTransport
