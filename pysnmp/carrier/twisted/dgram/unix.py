# Implements twisted-based UNIX domain socket transport
import sys
from twisted.internet import reactor
from pysnmp.carrier.base import AbstractTransportAddress
from pysnmp.carrier.twisted.dgram.base import DgramTwistedTransport
from pysnmp.carrier import error

domainName = snmpLocalDomain = (1, 3, 6, 1, 2, 1, 100, 1, 13)

class UnixTransportAddress(str, AbstractTransportAddress): pass

class UnixTwistedTransport(DgramTwistedTransport):
    addressType = UnixTransportAddress

    # AbstractTwistedTransport API
    
    def openClientMode(self, iface=''):
        try:
            self._lport = reactor.connectUNIXDatagram(iface, self)
        except Exception:
            raise error.CarrierError(sys.exc_info()[1])
        return self

    def openServerMode(self, iface=None):
        try:
            self._lport = reactor.listenUNIXDatagram(iface, self)
        except Exception:
            raise error.CarrierError(sys.exc_info()[1])
        
        return self

    def closeTransport(self):
        d = self._lport.stopListening()
        d and d.addCallback(lambda x: None)
        DgramTwistedTransport.closeTransport(self)

UnixTransport = UnixTwistedTransport
