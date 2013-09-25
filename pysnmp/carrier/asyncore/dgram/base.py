# Implements asyncore-based generic DGRAM transport
import socket, errno, sys
from pysnmp.carrier.asynsock.base import AbstractSocketTransport
from pysnmp.carrier import error
from pysnmp import debug

sockErrors = { # Ignore these socket errors
    errno.ESHUTDOWN: 1,
    errno.ENOTCONN: 1,
    errno.ECONNRESET: 0,
    errno.ECONNREFUSED: 0,
    errno.EAGAIN: 0,
    errno.EWOULDBLOCK: 0
    }
if hasattr(errno, 'EBADFD'):
    # bad FD may happen upon FD closure on n-1 select() event
    sockErrors[errno.EBADFD] = 1

class DgramSocketTransport(AbstractSocketTransport):
    sockType = socket.SOCK_DGRAM
    retryCount = 3; retryInterval = 1
    def __init__(self, sock=None, sockMap=None):
        self.__outQueue = []
        AbstractSocketTransport.__init__(self, sock, sockMap)
        
    def openClientMode(self, iface=None):
        if iface is not None:
            try:
                self.socket.bind(iface)
            except socket.error:
                raise error.CarrierError('bind() for %s failed: %s' % (iface is None and "<all local>" or iface, sys.exc_info()[1],))
        return self
    
    def openServerMode(self, iface):
        try:
            self.socket.bind(iface)
        except socket.error:
            raise error.CarrierError('bind() for %s failed: %s' % (iface, sys.exc_info()[1],))
        return self

    def sendMessage(self, outgoingMessage, transportAddress):
        self.__outQueue.append(
            (outgoingMessage, transportAddress)
            )
        debug.logger & debug.flagIO and debug.logger('sendMessage: outgoingMessage queued (%d octets) %s' % (len(outgoingMessage), debug.hexdump(outgoingMessage)))

    def normalizeAddress(self, transportAddress): return transportAddress

    def __getsockname(self):
        # one evil OS does not seem to support getsockname() for DGRAM sockets
        try:
            return self.socket.getsockname()
        except:
            return ('0.0.0.0', 0)

    # asyncore API
    def handle_connect(self): pass
    def writable(self): return self.__outQueue
    def handle_write(self):
        outgoingMessage, transportAddress = self.__outQueue.pop(0)
        debug.logger & debug.flagIO and debug.logger('handle_write: transportAddress %r -> %r outgoingMessage (%d octets) %s' % (self.__getsockname(), transportAddress, len(outgoingMessage), debug.hexdump(outgoingMessage)))
        if not transportAddress:
            debug.logger & debug.flagIO and debug.logger('handle_write: missing dst address, loosing outgoing msg')
            return
        try:
            self.socket.sendto(outgoingMessage, transportAddress)
        except socket.error:
            if sys.exc_info()[1].args[0] in sockErrors:
                debug.logger & debug.flagIO and debug.logger('handle_write: ignoring socket error %s' % (sys.exc_info()[1],))
            else:
                raise error.CarrierError('sendto() failed for %s: %s' % (transportAddress, sys.exc_info()[1]))
            
    def readable(self): return 1
    def handle_read(self):
        try:
            incomingMessage, transportAddress = self.socket.recvfrom(65535)
            transportAddress = self.normalizeAddress(transportAddress)
            debug.logger & debug.flagIO and debug.logger('handle_read: transportAddress %r -> %r incomingMessage (%d octets) %s' % (transportAddress, self.__getsockname(), len(incomingMessage), debug.hexdump(incomingMessage)))
            if not incomingMessage:
                self.handle_close()
                return
            else:
                self._cbFun(self, transportAddress, incomingMessage)
                return
        except socket.error:
            if sys.exc_info()[1].args[0] in sockErrors:
                debug.logger & debug.flagIO and debug.logger('handle_read: known socket error %s' % (sys.exc_info()[1],))
                sockErrors[sys.exc_info()[1].args[0]] and self.handle_close()
                return
            else:
                raise error.CarrierError('recvfrom() failed: %s' % (sys.exc_info()[1],))
    def handle_close(self): pass # no datagram connection
