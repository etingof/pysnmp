try:
    from sys import version_info
except ImportError:
    version_info = ( 0, 0 )   # a really early version
from time import time
from select import select
from pysnmp.carrier import base

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

class AsynsockDispatcher(base.AbstractTransportDispatcher):
    """Implements I/O over asynchronous sockets"""
    def __init__(self):
        self.__sockMap = {}
        self.timeout = 1.0
        base.AbstractTransportDispatcher.__init__(self)

    def registerTransport(self, tDomain, t):
        base.AbstractTransportDispatcher.registerTransport(self, tDomain, t)
        t.registerSocket(self.__sockMap)

    def unregisterTransport(self, tDomain):
        self.getTransport(tDomain).unregisterSocket(self.__sockMap)
        base.AbstractTransportDispatcher.unregisterTransport(self, tDomain)

    def runDispatcher(self):
        while 1:
            poll(self.timeout, self.__sockMap)
            self.handleTimerTick(time())
            if not self._doDispatchFlag:
                break
