#
#  Copyright (C) 2008 Truelite Srl <info@truelite.it>
#  Author: Filippo Giunchedi <filippo@truelite.it>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License Version 2
#  as published by the Free Software Foundation
#
# Description: Transport dispatcher based on twisted.internet.reactor
#
from time import time
from twisted.internet import reactor, task
from pysnmp.carrier.base import AbstractTransportDispatcher
from pysnmp.carrier import error

class TwistedDispatcher(AbstractTransportDispatcher):
    """TransportDispatcher based on twisted.internet.reactor"""
    def __init__(self, *args, **kwargs):
        AbstractTransportDispatcher.__init__(self)
        self.__transportCount = 0
        self.timeout = kwargs.get('timeout', 1.0)
        self.loopingcall = task.LoopingCall(self.handleTimeout)

    def handleTimeout(self):
        self.handleTimerTick(time())

    def runDispatcher(self, timeout=0.0):
        if not reactor.running:
            try:
                reactor.run()
            except Exception, why:
                raise error.CarrierError(why)

    # jobstarted/jobfinished might be okay as-is

    def registerTransport(self, tDomain, transport):
        if not self.loopingcall.running and self.timeout > 0:
            self.loopingcall.start(self.timeout, now = False)
        AbstractTransportDispatcher.registerTransport(
            self, tDomain, transport
            )
        self.__transportCount = self.__transportCount + 1

    def unregisterTransport(self, tDomain):
        t = AbstractTransportDispatcher.getTransport(self, tDomain)
        if t is not None:
            AbstractTransportDispatcher.unregisterTransport(self, tDomain)
            t.closeTransport()
            self.__transportCount = self.__transportCount - 1

        # The last transport has been removed, stop the timeout
        if self.__transportCount > 0 and self.loopingcall.running:
            self.loopingcall.stop()
