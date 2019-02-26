#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from twisted.internet import reactor

from pysnmp.carrier import error
from pysnmp.carrier.base import AbstractTransportAddress
from pysnmp.carrier.twisted.dgram.base import DgramTwistedTransport

DOMAIN_NAME = SNMP_UDP_DOMAIN = (1, 3, 6, 1, 6, 1, 1)


class UdpTransportAddress(tuple, AbstractTransportAddress):
    pass


class UdpTwistedTransport(DgramTwistedTransport):
    ADDRESS_TYPE = UdpTransportAddress
    _lport = None

    # AbstractTwistedTransport API

    def openClientMode(self, iface=None):
        if iface is None:
            iface = ('', 0)

        try:
            self._lport = reactor.listenUDP(iface[1], self, iface[0])

        except Exception as exc:
            raise error.CarrierError(exc)

        return self

    def openServerMode(self, iface):
        try:
            self._lport = reactor.listenUDP(iface[1], self, iface[0])

        except Exception as exc:
            raise error.CarrierError(exc)

        return self

    def closeTransport(self):
        if self._lport is not None:
            deferred = self._lport.stopListening()
            if deferred:
                deferred.addCallback(lambda x: None)

            DgramTwistedTransport.closeTransport(self)


UdpTransport = UdpTwistedTransport
