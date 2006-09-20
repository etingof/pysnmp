"""Abstract I/O dispatcher. Defines standard dispatcher API"""
from pysnmp.carrier import error

class AbstractTransportDispatcher:
    def __init__(self):
        self.__transports = {}
        self.__jobs = {}
        self.__recvCbFun = self.__timerCbFun = None
        self.__timeToGo = 0

    def _cbFun(self, incomingTransport, transportAddress, incomingMessage):
        for name, transport in self.__transports.items():
            if transport is incomingTransport:
                transportDomain = name
                break
        else:
            raise error.CarrierError(
                'Unregistered transport %s' % incomingTransport
                )
        if self.__recvCbFun is None:
            raise error.CarrierError(
                'Receive callback not registered -- loosing incoming event'
                )
        self.__recvCbFun(
            self, transportDomain, transportAddress, incomingMessage
            )

    # Dispatcher API
    
    def registerRecvCbFun(self, recvCbFun):
        if self.__recvCbFun is not None:
            raise error.CarrierError(
                'Receive callback already registered: %s' % self.__recvCbFun
                )
        self.__recvCbFun = recvCbFun

    def unregisterRecvCbFun(self):
        self.__recvCbFun = None

    def registerTimerCbFun(self, timerCbFun):
        if self.__timerCbFun is not None:
            raise error.CarrierError(
                'Callback already registered: %s' % self.__timerCbFun
                )
        self.__timerCbFun = timerCbFun

    def unregisterTimerCbFun(self):
        self.__timerCbFun = None

    def registerTransport(self, tDomain, transport):
        if self.__transports.has_key(tDomain):
            raise error.CarrierError(
                'Transport %s already registered' % tDomain
                )
        transport.registerCbFun(self._cbFun)
        self.__transports[tDomain] = transport

    def unregisterTransport(self, tDomain):
        if not self.__transports.has_key(tDomain):
            raise error.CarrierError(
                'Transport %s not registered' % tDomain
                )
        self.__transports[tDomain].unregisterCbFun()
        del self.__transports[tDomain]

    def getTransport(self, transportDomain):
        return self.__transports.get(transportDomain)

    def sendMessage(
        self, outgoingMessage, transportDomain, transportAddress
        ):
        transport = self.__transports.get(transportDomain)
        if transport is None:
            raise error.CarrierError(
                'No suitable transport domain for %s' % (transportDomain,)
                )
        transport.sendMessage(outgoingMessage, transportAddress)

    def handleTimerTick(self, timeNow):
        if self.__timerCbFun and self.__timeToGo < timeNow:
            self.__timerCbFun(timeNow)
            self.__timeToGo = timeNow + 1

    def jobStarted(self, jobId):
        self.__jobs[jobId] = self.__jobs.get(jobId, 0) + 1

    def jobFinished(self, jobId):
        self.__jobs[jobId] = self.__jobs[jobId] - 1
        if self.__jobs[jobId] == 0:
            del self.__jobs[jobId]

    def jobsArePending(self):
        if self.__jobs:
            return 1
        else:
            return 0

    def runDispatcher(self, timeout=0.0):
        raise error.CarrierError('Method not implemented')
        
    def closeDispatcher(self):
        for tDomain in self.__transports.keys():
            self.__transports[tDomain].closeTransport()
            self.unregisterTransport(tDomain)
        self.unregisterRecvCbFun()
        self.unregisterTimerCbFun()
