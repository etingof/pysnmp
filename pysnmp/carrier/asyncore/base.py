#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import socket
import sys
import asyncore
from pysnmp.carrier import error
from pysnmp.carrier.base import AbstractTransport
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp import debug


class AbstractSocketTransport(asyncore.dispatcher, AbstractTransport):
    PROTO_TRANSPORT_DISPATCHER = AsyncoreDispatcher
    SOCK_FAMILY = SOCK_TYPE = None
    RETRY_COUNT = 0
    RETRY_INTERVAL = 0
    BUFFER_SIZE = 131070

    # noinspection PyUnusedLocal
    def __init__(self, sock=None, sockMap=None):
        asyncore.dispatcher.__init__(self)
        if sock is None:
            if self.SOCK_FAMILY is None:
                raise error.CarrierError(
                    'Address family %s not supported' % self.__class__.__name__
                )
            if self.SOCK_TYPE is None:
                raise error.CarrierError(
                    'Socket type %s not supported' % self.__class__.__name__
                )
            try:
                sock = socket.socket(self.SOCK_FAMILY, self.SOCK_TYPE)
            except socket.error as exc:
                raise error.CarrierError('socket() failed: %s' % exc)

            try:
                for b in socket.SO_RCVBUF, socket.SO_SNDBUF:
                    bsize = sock.getsockopt(socket.SOL_SOCKET, b)
                    if bsize < self.BUFFER_SIZE:
                        sock.setsockopt(socket.SOL_SOCKET, b, self.BUFFER_SIZE)
                        debug.logger & debug.FLAG_IO and debug.logger('%s: socket %d buffer size increased from %d to %d for buffer %d' % (self.__class__.__name__, sock.fileno(), bsize, self.BUFFER_SIZE, b))
            except Exception as exc:
                debug.logger & debug.FLAG_IO and debug.logger('%s: socket buffer size option mangling failure for buffer: %s' % (self.__class__.__name__, exc))

        # The socket map is managed by the AsyncoreDispatcher on
        # which this transport is registered. Here we just prepare
        # socket and postpone transport registration at dispatcher
        # till AsyncoreDispatcher invokes registerSocket()

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(0)
        self.set_socket(sock)

    def __hash__(self):
        return hash(self.socket)

    # The following two methods are part of base class so here we overwrite
    # them to separate socket management from dispatcher registration tasks.
    # These two are just for dispatcher registration.
    def add_channel(self, map=None):
        if map is not None:
            map[self._fileno] = self
            self.connected = True

    def del_channel(self, map=None):
        if map is not None and self._fileno in map:
            del map[self._fileno]
            self.connected = False

    def registerSocket(self, sockMap=None):
        self.add_channel(sockMap)

    def unregisterSocket(self, sockMap=None):
        self.del_channel(sockMap)

    def closeTransport(self):
        AbstractTransport.closeTransport(self)
        self.close()

    # asyncore API

    def handle_close(self):
        raise error.CarrierError('Transport unexpectedly closed')

    def handle_error(self):
        exc = sys.exc_info()[1]
        raise exc
