try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version
from time import time
from select import select
from pysnmp.carrier.base import AbstractTransportDispatcher

__all__ = [ 'AsynsockDispatcher' ]

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
    def __init__(self, **kwargs):
        self.__sockMap = {}
        self.timeout = 1.0
        apply(AbstractTransportDispatcher.__init__, [self], kwargs)

    def registerTransports(self, **kwargs):
        apply(AbstractTransportDispatcher.registerTransports, (self,), kwargs)
        for transport in kwargs.values():
            transport.registerSocket(self.__sockMap)

    def unregisterTransports(self, *args):
        for name in args:
            self.getTransport(name).unregisterSocket(self.__sockMap)
        apply(
            AbstractTransportDispatcher.unregisterTransports, (self, ) + args
            )

    def runDispatcher(self, liveForever=1):
        self.doDispatchFlag = liveForever
        while 1:
            poll(self.timeout, self.__sockMap)
            self.handleTimerTick(time())
            if not self.doDispatchFlag:
                break
            
# XXX doDispatchFlag is needed?
