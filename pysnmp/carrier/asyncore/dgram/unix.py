# Implements asyncore-based UNIX transport domain
from os import remove, tmpnam
from socket import AF_UNIX
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpLocalDomain = (1, 3, 6, 1, 2, 1, 100, 1, 13)

class UnixSocketTransport(DgramSocketTransport):
    sockFamily = AF_UNIX

    def openClientMode(self, iface=None):
        if iface is None:
            iface = tmpnam()  # UNIX domain sockets must be explicitly bound
        DgramSocketTransport.openClientMode(self, iface)
        self.__iface = iface
        return self

    def openServerMode(self, iface):
        DgramSocketTransport.openServerMode(self, iface)
        self.__iface = iface
        return self

    def closeTransport(self):
        DgramSocketTransport.closeTransport(self)
        try:
            remove(self.__iface)
        except:
            pass

UnixTransport = UnixSocketTransport

# Compatibility stub
UnixDgramSocketTransport = UnixSocketTransport
