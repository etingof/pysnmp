"""Abstract I/O dispatcher. Defines standard dispatcher API"""
from pysnmp.carrier import error

class AbstractTransportDispatcher:
    def __init__(self, **kwargs):
        self.doDispatchFlag = 1
        self.__transports = {}
        self.__recvCbFun = self.__timerCbFun = None
        apply(self.registerTransports, [], kwargs)

    def _cbFun(self, incomingTransport, transportAddress, incomingMessage):
        for name, transport in self.__transports.items():
            if transport is incomingTransport:
                transportDomain = name
                break
        else:
            raise error.BadArgumentError(
                'Unregistered transport %s' % incomingTransport
                )
        if self.__recvCbFun is None:
            raise error.BadArgumentError(
                'Receive callback not registered -- loosing incoming event'
                )
        self.__recvCbFun(
            self, transportDomain, transportAddress, incomingMessage
            )

    # Dispatcher API
    
    def registerRecvCbFun(self, recvCbFun):
        if self.__recvCbFun is not None:
            raise error.BadArgumentError(
                'Receive callback already registered: %s' % self.__recvCbFun
                )
        self.__recvCbFun = recvCbFun

    def unregisterRecvCbFun(self):
        self.__recvCbFun = None

    def registerTimerCbFun(self, timerCbFun):
        if self.__timerCbFun is not None:
            raise error.BadArgumentError(
                'Callback already registered: %s' % self.__timerCbFun
                )
        self.__timerCbFun = timerCbFun

    def unregisterTimerCbFun(self):
        self.__timerCbFun = None

    def closeTransports(self, *args):
        if not args: args = self.__transports.keys()
        for name in args:
            if not self.__transports.has_key(name):
                raise error.BadArgumentError(
                    'Transport %s not registered' % name
                    )
            self.__transports[name].closeTransport()

    def registerTransports(self, **kwargs):
        for name, transport in kwargs.items():
            if self.__transports.has_key(name):
                raise error.BadArgumentError(
                    'Transport %s already registered' % name
                    )
            transport.registerCbFun(self._cbFun)
            self.__transports[name] = transport

    def unregisterTransports(self, *args):
        if not args: args = self.__transports.keys()
        for name in args:
            if not self.__transports.has_key(name):
                raise error.BadArgumentError(
                    'Transport %s not registered' % name
                    )
            self.__transports[name].unregisterCbFun()
            del self.__transports[name]

    def getTransport(self, transportDomain):
        return self.__transports.get(transportDomain)
        
    def sendMessage(
        self, outgoingMessage, transportDomain, transportAddress
        ):
        transport = self.__transports.get(transportDomain)
        if transport is None:
            raise error.BadArgumentError(
                'No suitable transport domain for %s' % transportDomain
                )
        transport.sendMessage(outgoingMessage, transportAddress)

    def handleTimerTick(self, timeNow):
        if self.__timerCbFun:
            self.__timerCbFun(timeNow)

    def runDispatcher(self, timeout=0.0):
        raise error.BadArgumentError('Method not implemented')

    def closeDispatcher(self):
        self.closeTransports()
        self.unregisterTransports()
        self.unregisterRecvCbFun()
        self.unregisterTimerCbFun()
        
# XXX
# support mapping API?
