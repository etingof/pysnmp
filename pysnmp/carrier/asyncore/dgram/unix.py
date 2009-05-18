"""Implements asyncore-based UNIX transport domain"""
from os import remove
from socket import AF_UNIX
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpLocalDomain = (1, 3, 6, 1, 2, 1, 100, 1, 13)

class UnixSocketTransport(DgramSocketTransport):
    sockFamily = AF_UNIX

    def closeTransport(self):
        DgramSocketTransport.closeTransport(self)
        try:
            remove(self._iface)
        except:
            pass

UnixTransport = UnixSocketTransport

# Compatibility stub
UnixDgramSocketTransport = UnixSocketTransport
