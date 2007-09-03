"""Defines standard API to asyncore-based transport"""
try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version
import socket, sys
import asyncore
from pysnmp.carrier import error

class AbstractSocketTransport(asyncore.dispatcher):
    sockFamily = sockType = None
    retryCount = 0; retryInterval = 0
    def __init__(self, sock=None, sockMap=None):
        if sock is None:
            try:
                sock = socket.socket(self.sockFamily, self.sockType)
            except socket.error, why:
                raise error.CarrierError('socket() failed: %s' % why)
        if sockMap is None:
            # The socket map is managed by the AsynsockDispatcher on
            # which this transport is registered, so this is a fake
            # socket map to avoid registering with deafult asyncore map.
            sockMap = {}
        # Old asyncore doesn't allow socket_map param in constructor
        if version_info < (2, 0):
            # Taken from dispatcher.__init__()
            self.socket = sock
            self.add_channel(sockMap)
            self.socket.setblocking(0)
            self.connected = 1
        else:
            asyncore.dispatcher.__init__(self, sock, sockMap)

    # Old asyncore doesn't allow socket_map param
    if version_info < (2, 0):
        def add_channel (self, sockMap=None):
            if sockMap is None:
                sockMap = asyncore.socket_map
            sockMap[self] = self

        def del_channel (self, sockMap=None):
            if sockMap is None:
                sockMap = asyncore.socket_map
            if sockMap.has_key(self):
                del sockMap[self]

    def registerSocket(self, sockMap=None):
        self.add_channel(sockMap)
        
    def unregisterSocket(self, sockMap=None):
        self.del_channel(sockMap)
        
    # Public API
    
    def openClientMode(self, iface=None):
        raise error.CarrierError('Method not implemented')

    def openServerMode(self, iface=None):
        raise error.CarrierError('Method not implemented')
        
    def sendMessage(self, outgoingMessage, transportAddress):
        raise error.CarrierError('Method not implemented')

    def registerCbFun(self, cbFun):
        self._cbFun = cbFun

    def unregisterCbFun(self):
        self._cbFun = None

    def closeTransport(self):
        self.unregisterCbFun()
        self.close()
        
    # asyncore API
    def handle_close(self): raise error.CarrierError(
        'Transport unexpectedly closed'
        )
    def handle_error(self): raise

