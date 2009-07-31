"""Implements twisted-based generic DGRAM transport"""
from time import time
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from pysnmp.carrier.twisted.base import AbstractTwistedTransport
from pysnmp.carrier import error
from pysnmp import debug

class DgramTwistedTransport(DatagramProtocol, AbstractTwistedTransport):
    """Base Twisted datagram Transport, to be used with TwistedDispatcher"""

    # Twisted Datagram API
    
    def datagramReceived(self, datagram, address):
        if self._cbFun is None:
            raise error.CarrierError('Unable to call cbFun')
        else:
            # Callback fun is called through callLater() in attempt
            # to make Twisted timed calls work under high load.
            reactor.callLater(0, self._cbFun, self, address, datagram)

    def startProtocol(self):
        debug.logger & debug.flagIO and debug.logger('startProtocol: invoked')
        while self._writeQ:
            outgoingMessage, transportAddress = self._writeQ.pop(0)
            debug.logger & debug.flagIO and debug.logger('startProtocol: transportAddress %s outgoingMessage %s' % (transportAddress, repr(outgoingMessage)))
            try:
                self.transport.write(outgoingMessage, transportAddress)
            except Exception, why:
                raise error.CarrierError('Twisted exception: %s' % (why,))

    def stopProtocol(self):
        debug.logger & debug.flagIO and debug.logger('stopProtocol: invoked')
        self.closeTransport()

    def sendMessage(self, outgoingMessage, transportAddress):
        debug.logger & debug.flagIO and debug.logger('startProtocol: %s transportAddress %s outgoingMessage %s' % ((self.transport is None and "queuing" or "sending"), transportAddress, repr(outgoingMessage)))        
        if self.transport is None:
            self._writeQ.append((outgoingMessage, transportAddress))
        else:
            try:
                self.transport.write(outgoingMessage, transportAddress)
            except Exception, why:
                raise error.CarrierError('Twisted exception: %s' % (why,))
