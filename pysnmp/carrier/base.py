"""Abstract I/O dispatcher. Defines standard dispatcher API"""
from pysnmp.carrier import error

class TimerCallable:
    def __init__(self, cbFun, callInterval):
        self.__cbFun = cbFun
        self.__callInterval = callInterval
        self.__nextCall = 0
        
    def __call__(self, timeNow):
        if self.__nextCall <= timeNow:
            self.__cbFun(timeNow)
            self.__nextCall = timeNow + self.__callInterval

    def __eq__(self, cbFun): return self.__cbFun == cbFun
    def __ne__(self, cbFun): return self.__cbFun != cbFun
    def __lt__(self, cbFun): return self.__cbFun < cbFun
    def __le__(self, cbFun): return self.__cbFun <= cbFun
    def __gt__(self, cbFun): return self.__cbFun > cbFun
    def __ge__(self, cbFun): return self.__cbFun >= cbFun
    
class AbstractTransportDispatcher:
    def __init__(self):
        self.__transports = {}
        self.__jobs = {}
        self.__recvCbFun = None
        self.__timerCallables = []
        self.__ticks = 0
        self.__timerResolution = 0.5
        self.__nextTime = 0
        
    def _cbFun(self, incomingTransport, transportAddress, incomingMessage):
        for name, transport in self.__transports.items():
            if transport is incomingTransport:
                transportDomain = name
                break
        else:
            raise error.CarrierError(
                'Unregistered transport %s' % (incomingTransport,)
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

    def registerTimerCbFun(self, timerCbFun, tickInterval=None):
        if not tickInterval:
            tickInterval = self.__timerResolution
        self.__timerCallables.append(TimerCallable(timerCbFun, tickInterval))

    def unregisterTimerCbFun(self, timerCbFun=None):
        if timerCbFun is None:
            self.__timerCallables = []
        else:
            self.__timerCallables.remove(timerCbFun)

    def registerTransport(self, tDomain, transport):
        if tDomain in self.__transports:
            raise error.CarrierError(
                'Transport %s already registered' % (tDomain,)
                )
        transport.registerCbFun(self._cbFun)
        self.__transports[tDomain] = transport

    def unregisterTransport(self, tDomain):
        if tDomain not in self.__transports:
            raise error.CarrierError(
                'Transport %s not registered' % (tDomain,)
                )
        self.__transports[tDomain].unregisterCbFun()
        del self.__transports[tDomain]

    def getTransport(self, transportDomain):
        if transportDomain in self.__transports:
            return self.__transports[transportDomain]
        raise error.CarrierError(
            'Transport %s not registered' % (transportDomain,)
            )
        
    def sendMessage(
        self, outgoingMessage, transportDomain, transportAddress
        ):
        if transportDomain in self.__transports:
            self.__transports[transportDomain].sendMessage(
                outgoingMessage, transportAddress
                )
        else:
            raise error.CarrierError(
                'No suitable transport domain for %s' % (transportDomain,)
                )

    def getTimerResolution(self):
        return self.__timerResolution
    def setTimerResolution(self, timerResolution):
        if timerResolution < 0.01 or timerResolution > 10:
            raise error.CarrierError('Impossible timer resolution')
        self.__timerResolution = timerResolution
    
    def getTimerTicks(self): return self.__ticks
    
    def handleTimerTick(self, timeNow):
        if self.__nextTime == 0:   # initial initialization
            self.__nextTime = timeNow + self.__timerResolution

        if self.__nextTime > timeNow:
            return
        
        self.__ticks += 1
        self.__nextTime = timeNow + self.__timerResolution

        for timerCallable in self.__timerCallables:
            timerCallable(timeNow)

    def jobStarted(self, jobId):
        if jobId in self.__jobs:
            self.__jobs[jobId] = self.__jobs[jobId] + 1
        else:
            self.__jobs[jobId] = 1

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
        for tDomain in list(self.__transports):
            self.__transports[tDomain].closeTransport()
            self.unregisterTransport(tDomain)
        self.unregisterRecvCbFun()
        self.unregisterTimerCbFun()
