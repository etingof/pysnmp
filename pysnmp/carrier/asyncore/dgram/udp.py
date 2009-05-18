"""Implements asyncore-based UDP transport domain"""
from socket import AF_INET
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpUDPDomain = (1, 3, 6, 1, 6, 1, 1)

class UdpSocketTransport(DgramSocketTransport):
    sockFamily = AF_INET

UdpTransport = UdpSocketTransport
