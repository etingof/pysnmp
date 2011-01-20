from time import time
from select import select
from asyncore import socket_map
from pysnmp.carrier.base import AbstractTransportDispatcher
from asyncore import poll

class AsynsockDispatcher(AbstractTransportDispatcher):
    """Implements I/O over asynchronous sockets"""
    def __init__(self):
        self.__sockMap = {} # use own map for MT safety
        self.timeout = 0.5
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
            poll(timeout and timeout or self.timeout, self.__sockMap)
            self.handleTimerTick(time())
