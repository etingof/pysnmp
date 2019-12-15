#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from asyncore import loop
from asyncore import socket_map
from sys import exc_info
from time import time
from traceback import format_exception

from pysnmp.carrier.base import AbstractTransportDispatcher
from pysnmp.error import PySnmpError


class AsyncoreDispatcher(AbstractTransportDispatcher):
    def __init__(self):
        # use own map for MT safety
        self.__sockMap = {}
        AbstractTransportDispatcher.__init__(self)

    def getSocketMap(self):
        return self.__sockMap

    def setSocketMap(self, sockMap=socket_map):
        self.__sockMap = sockMap

    def registerTransport(self, transportDomain, transport):
        AbstractTransportDispatcher.registerTransport(
            self, transportDomain, transport)
        transport.registerSocket(self.__sockMap)

    def unregisterTransport(self, transportDomain):
        self.getTransport(transportDomain).unregisterSocket(self.__sockMap)
        AbstractTransportDispatcher.unregisterTransport(self, transportDomain)

    def transportsAreWorking(self):
        for transport in self.__sockMap.values():
            if transport.writable():
                return True

    def runDispatcher(self, timeout=0.0):
        while self.jobsArePending() or self.transportsAreWorking():
            try:
                loop(timeout or self.getTimerResolution(),
                     use_poll=True, map=self.__sockMap, count=1)

            except Exception:
                raise PySnmpError(
                    'poll error: %s' % ';'.join(format_exception(*exc_info())))

            self.handleTimerTick(time())
