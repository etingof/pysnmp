"""Implements asyncore-based UNIX transport domain"""
from os import remove
from socket import AF_UNIX
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

class UnixDgramSocketTransport(DgramSocketTransport):
    sockFamily = AF_UNIX

    def closeTransport(self):
        DgramSocketTransport.closeTransport(self)
        try:
            remove(self._iface)
        except:
            pass
