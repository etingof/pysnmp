try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version
from time import time
from select import select
from asyncore import socket_map
from pysnmp.carrier.base import AbstractTransportDispatcher

# Old asyncore doesn't allow socket_map param at poll
if version_info < (2, 0):
    def poll(timeout, socket_map):
        if not socket_map:
            return
        sockets = socket_map.keys()
        r = filter(lambda x: x.readable(), sockets)
        w = filter(lambda x: x.writable(), sockets)

        (r,w,e) = select(r, w, [], timeout)

        for x in r:
            try:
                x.handle_read_event()
            except:
                x.handle_error()
        for x in w:
            try:
                x.handle_write_event()
            except:
                x.handle_error()
else:
    from asyncore import poll

class AsynsockDispatcher(AbstractTransportDispatcher):
    """Implements I/O over asynchronous sockets"""
    def __init__(self):
        self.__sockMap = {} # use own map for MT safety
        self.timeout = 1.0
        AbstractTransportDispatcher.__init__(self)

    def getSocketMap(self): return self.__sockMap
    def setSocketMap(self, sockMap=socket_map): self.__sockMap = sockMap
    
    def registerTransport(self, tDomain, t):
        AbstractTransportDispatcher.registerTransport(self, tDomain, t)
        t.registerSocket(self.__sockMap)

    def unregisterTransport(self, tDomain):
        self.getTransport(tDomain).unregisterSocket(self.__sockMap)
        AbstractTransportDispatcher.unregisterTransport(self, tDomain)

    def transportsAreWorking(self):
        for transport in self.__sockMap.values():
            if transport.writable():
                return 1
        return 0
    
    def runDispatcher(self, timeout=0.0):
        while self.jobsArePending() or self.transportsAreWorking():
            poll(self.timeout, self.__sockMap)
            self.handleTimerTick(time())
