"""Implements asyncore-based UDP6 transport domain"""
from socket import AF_INET6
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpUDP6Domain = (1, 3, 6, 1, 2, 1, 100, 1, 2)

class Udp6SocketTransport(DgramSocketTransport):
    sockFamily = AF_INET6

Udp6Transport = Udp6SocketTransport
