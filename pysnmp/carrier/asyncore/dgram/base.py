"""Implements asyncore-based generic DGRAM transport"""
import socket, errno
from pysnmp.carrier.asynsock.base import AbstractSocketTransport
from pysnmp.carrier import error

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
                raise error.CarrierError('bind() failed: %s' % why)
        return self
    
    def openServerMode(self, iface):
        try:
            self.socket.bind(iface)
        except socket.error, why:
            raise error.CarrierError('bind() failed: %s' % why)
        self._iface = iface
        return self

    def rewriteAddress(self, transportAddress): return transportAddress
    
    def sendMessage(self, outgoingMessage, transportAddress):
        self.__outQueue.append(
            (outgoingMessage, self.rewriteAddress(transportAddress))
            )

    # asyncore API
    def handle_connect(self): pass
    def writable(self): return self.__outQueue
    def handle_write(self):
        outgoingMessage, transportAddress = self.__outQueue.pop()
        try:
            self.socket.sendto(outgoingMessage, transportAddress)
        except socket.error, why:
            if why[0] != socket.EWOULDBLOCK:
                raise socket.error, why
    def readable(self): return 1
    def handle_read(self):
        try:
            incomingMessage, transportAddress = self.socket.recvfrom(65535)
            if not incomingMessage:
                self.handle_close()
                return
            else:
                self._cbFun(self, transportAddress, incomingMessage)
                return
        except socket.error, why:
            # winsock sometimes throws ENOTCONN
            if why[0] in (socket.ECONNRESET, socket.ENOTCONN, socket.ESHUTDOWN):
                self.handle_close()
                return
            else:
                raise socket.error, why
