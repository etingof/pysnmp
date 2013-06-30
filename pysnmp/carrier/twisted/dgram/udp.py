# Implements twisted-based UDP transport
import sys
from twisted.internet import reactor
from pysnmp.carrier.twisted.dgram.base import DgramTwistedTransport
from pysnmp.carrier import error

domainName = snmpUDPDomain = (1, 3, 6, 1, 6, 1, 1)

class UdpTwistedTransport(DgramTwistedTransport):
    # AbstractTwistedTransport API
    
    def openClientMode(self, iface=('', 0)):
        try:
            self._lport = reactor.listenUDP(iface[1], self, iface[0])
        except Exception:
            raise error.CarrierError(sys.exc_info()[1])
        return self

    def openServerMode(self, iface=('', 161)):
        try:
            self._lport = reactor.listenUDP(iface[1], self, iface[0])
        except Exception:
            raise error.CarrierError(sys.exc_info()[1])
        return self

    def closeTransport(self):
        d = self._lport.stopListening()
        d and d.addCallback(lambda x: None)
        DgramTwistedTransport.closeTransport(self)

UdpTransport = UdpTwistedTransport
