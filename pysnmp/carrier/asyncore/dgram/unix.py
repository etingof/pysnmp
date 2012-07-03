# Implements asyncore-based UNIX transport domain
import os, sys
if sys.version_info[0] < 3:
    tmpnam = os.tmpnam
else:
    import random
    random.seed()
    def tmpnam():
        f = ''
        while len(f) < 8:
            f += chr(random.randrange(65, 91)) + \
                 chr(random.randrange(97, 123))
        return os.path.sep + 'tmp' + os.path.sep + 'snmpsim' + f
try:
    from socket import AF_UNIX
except ImportError:
    AF_UNIX = None
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpLocalDomain = (1, 3, 6, 1, 2, 1, 100, 1, 13)

class UnixSocketTransport(DgramSocketTransport):
    sockFamily = AF_UNIX

    def openClientMode(self, iface=None):
        if iface is None:
            iface = tmpnam()  # UNIX domain sockets must be explicitly bound
        if os.path.exists(iface):
            os.remove(iface)
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
            os.remove(self.__iface)
        except:
            pass

UnixTransport = UnixSocketTransport

# Compatibility stub
UnixDgramSocketTransport = UnixSocketTransport
