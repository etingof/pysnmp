"""Implements asyncore-based UDP6 transport domain"""
try:
    from socket import AF_INET6
except:
    AF_INET6 = None
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpUDP6Domain = (1, 3, 6, 1, 2, 1, 100, 1, 2)

class Udp6SocketTransport(DgramSocketTransport):
    sockFamily = AF_INET6

Udp6Transport = Udp6SocketTransport
