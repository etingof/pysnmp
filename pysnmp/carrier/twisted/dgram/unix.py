"""Implements twisted-based UNIX domain socket transport"""
from twisted.internet import reactor
from pysnmp.carrier.twisted.dgram.base import DgramTwistedTransport
from pysnmp.carrier import error

domainName = snmpLocalDomain = (1, 3, 6, 1, 2, 1, 100, 1, 13)

class UnixTwistedTransport(DgramTwistedTransport):
    # AbstractTwistedTransport API
    
    def openClientMode(self, iface=''):
        try:
            self._lport = reactor.connectUNIXDatagram(iface, self)
        except Exception, why:
            raise error.CarrierError(why)
        return self

    def openServerMode(self, iface=None):
        try:
            self._lport = reactor.listenUNIXDatagram(iface, self)
        except Exception, why:
            raise error.CarrierError(why)
        
        return self

UnixTransport = UnixTwistedTransport