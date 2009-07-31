"""Implements twisted-based UDP transport"""
from twisted.internet import reactor
from pysnmp.carrier.twisted.dgram.base import DgramTwistedTransport
from pysnmp.carrier import error

domainName = snmpUDPDomain = (1, 3, 6, 1, 6, 1, 1)

class UdpTwistedTransport(DgramTwistedTransport):
    # AbstractTwistedTransport API
    
    def openClientMode(self, iface=''):
        try:
            self._lport = reactor.listenUDP(0, self, iface)
        except Exception, why:
            raise error.CarrierError(why)
        return self

    def openServerMode(self, iface=None):
        try:
            self._lport = reactor.listenUDP(iface[1], self, iface[0])
        except Exception, why:
            raise error.CarrierError(why)
        return self

UdpTransport = UdpTwistedTransport