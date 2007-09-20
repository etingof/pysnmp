"""Implements asyncore-based generic DGRAM transport"""
import socket, errno
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
try:
    # bad FD may happen upon FD closure on n-1 select() event
    sockErrors[errno.EBADFD] = 1
except AttributeError:
    # Windows sockets do not have EBADFD
    pass

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
            except socket.error, why:
                raise error.CarrierError('bind() failed: %s' % (why,))
        return self
    
    def openServerMode(self, iface):
        try:
            self.socket.bind(iface)
        except socket.error, why:
            raise error.CarrierError('bind() failed: %s' % (why,))
        self._iface = iface
        return self

    def sendMessage(self, outgoingMessage, transportAddress):
        self.__outQueue.append(
            (outgoingMessage, transportAddress)
            )

    # asyncore API
    def handle_connect(self): pass
    def writable(self): return self.__outQueue
    def handle_write(self):
        outgoingMessage, transportAddress = self.__outQueue.pop()
        debug.logger & debug.flagIO and debug.logger('handle_write: transportAddress %s outgoingMessage %s' % (transportAddress, repr(outgoingMessage)))
        try:
            self.socket.sendto(outgoingMessage, transportAddress)
        except socket.error, why:
            if sockErrors.has_key(why[0]):
                debug.logger & debug.flagIO and debug.logger('handle_write: ignoring socket error %s' % (why,))
            else:
                raise socket.error, why
            
    def readable(self): return 1
    def handle_read(self):
        try:
            incomingMessage, transportAddress = self.socket.recvfrom(65535)
            debug.logger & debug.flagIO and debug.logger('handle_read: transportAddress %s incomingMessage %s' % (transportAddress, repr(incomingMessage)))
            if not incomingMessage:
                self.handle_close()
                return
            else:
                self._cbFun(self, transportAddress, incomingMessage)
                return
        except socket.error, why:
            if sockErrors.has_key(why[0]):
                debug.logger & debug.flagIO and debug.logger('handle_read: known socket error %s' % (why,))
                sockErrors[why[0]] and self.handle_close()
                return
            else:
                raise socket.error, why
    def handle_close(self): pass # no datagram connection
