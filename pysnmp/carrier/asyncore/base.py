# Defines standard API to asyncore-based transport
import socket, sys
import asyncore
from pysnmp.carrier import error
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp import debug

class AbstractSocketTransport(asyncore.dispatcher):
    protoTransportDispatcher = AsynsockDispatcher
    sockFamily = sockType = None
    retryCount = 0; retryInterval = 0
    bufferSize = 131070
    def __init__(self, sock=None, sockMap=None):
        if sock is None:
            if self.sockFamily is None:
                raise error.CarrierError(
                    'Address family %s not supported' % self.__class__.__name__
                    )
            if self.sockType is None:
                raise error.CarrierError(
                    'Socket type %s not supported' % self.__class__.__name__
                    )
            try:
                sock = socket.socket(self.sockFamily, self.sockType)
            except socket.error:
                raise error.CarrierError('socket() failed: %s' % sys.exc_info()[1])

            try:
                for b in socket.SO_RCVBUF, socket.SO_SNDBUF:
                    bsize = sock.getsockopt(socket.SOL_SOCKET, b)
                    if bsize < self.bufferSize:
                        sock.setsockopt(socket.SOL_SOCKET, b, self.bufferSize)
                        debug.logger & debug.flagIO and debug.logger('%s: socket %d buffer size increased from %d to %d for buffer %d' % (self.__class__.__name__, sock.fileno(), bsize, self.bufferSize, b))
            except Exception:
                debug.logger & debug.flagIO and debug.logger('%s: socket buffer size option mangling failure for buffer %d: %s' % (self.__class__.__name__, b, sys.exc_info()[1]))

        if sockMap is None:
            # The socket map is managed by the AsynsockDispatcher on
            # which this transport is registered, so this is a fake
            # socket map to avoid registering with deafult asyncore map.
            sockMap = {}
        asyncore.dispatcher.__init__(self, sock, sockMap)

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

