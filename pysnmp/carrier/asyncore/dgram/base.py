#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import socket
import errno
import sys
from pysnmp.carrier.asyncore.base import AbstractSocketTransport
from pysnmp.carrier import sockfix, sockmsg, error
from pysnmp import debug

# Ignore these socket errors
SOCK_ERRORS = {errno.ESHUTDOWN: True,
               errno.ENOTCONN: True,
               errno.ECONNRESET: False,
               errno.ECONNREFUSED: False,
               errno.EAGAIN: False,
               errno.EWOULDBLOCK: False}

if hasattr(errno, 'EBADFD'):
    # bad FD may happen upon FD closure on n-1 select() event
    SOCK_ERRORS[errno.EBADFD] = True


class DgramSocketTransport(AbstractSocketTransport):
    SOCK_TYPE = socket.SOCK_DGRAM
    RETRY_COUNT = 3
    RETRY_INTERVAL = 1
    ADDRESS_TYPE = lambda x: x

    def __init__(self, sock=None, sockMap=None):
        self.__outQueue = []
        self._sendto = lambda s, b, a: s.sendto(b, a)

        def __recvfrom(s, sz):
            d, a = s.recvfrom(sz)
            return d, self.ADDRESS_TYPE(a)

        self._recvfrom = __recvfrom
        AbstractSocketTransport.__init__(self, sock, sockMap)

    def openClientMode(self, iface=None):
        if iface is not None:
            try:
                self.socket.bind(iface)
            except socket.error as exc:
                raise error.CarrierError(
                    'bind() for %s failed: %s' % (iface is None and "<all local>" or iface, exc))
        return self

    def openServerMode(self, iface):
        try:
            self.socket.bind(iface)
        except socket.error as exc:
            raise error.CarrierError('bind() for %s failed: %s' % (iface, exc))
        return self

    def enableBroadcast(self, flag=1):
        try:
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_BROADCAST, flag
            )
        except socket.error as exc:
            raise error.CarrierError('setsockopt() for SO_BROADCAST failed: %s' % exc)
        debug.logger & debug.FLAG_IO and debug.logger('enableBroadcast: %s option SO_BROADCAST on socket %s' % (flag and "enabled" or "disabled", self.socket.fileno()))
        return self

    def enablePktInfo(self, flag=1):
        if (not hasattr(self.socket, 'sendmsg') or
                not hasattr(self.socket, 'recvmsg')):
            raise error.CarrierError('sendmsg()/recvmsg() interface is not supported by this OS and/or Python version')

        try:
            if self.socket.family == socket.AF_INET:
                self.socket.setsockopt(socket.SOL_IP, socket.IP_PKTINFO, flag)

            if self.socket.family == socket.AF_INET6:
                self.socket.setsockopt(socket.SOL_IPV6, socket.IPV6_RECVPKTINFO, flag)

        except socket.error as exc:
            raise error.CarrierError('setsockopt() for %s failed: %s' % (self.socket.family == socket.AF_INET6 and "IPV6_RECVPKTINFO" or "IP_PKTINFO", exc))

        self._sendto = sockmsg.getSendTo(self.ADDRESS_TYPE)
        self._recvfrom = sockmsg.getRecvFrom(self.ADDRESS_TYPE)

        debug.logger & debug.FLAG_IO and debug.logger('enablePktInfo: %s option %s on socket %s' % (self.socket.family == socket.AF_INET6 and "IPV6_RECVPKTINFO" or "IP_PKTINFO", flag and "enabled" or "disabled", self.socket.fileno()))
        return self

    def enableTransparent(self, flag=1):
        try:
            if self.socket.family == socket.AF_INET:
                self.socket.setsockopt(
                    socket.SOL_IP, socket.IP_TRANSPARENT, flag
                )
            if self.socket.family == socket.AF_INET6:
                self.socket.setsockopt(
                    socket.SOL_IPV6, socket.IPV6_TRANSPARENT, flag
                )

        except socket.error as exc:
            raise error.CarrierError('setsockopt() for IP_TRANSPARENT failed: %s' % exc)

        except OSError:
            raise error.CarrierError('IP_TRANSPARENT socket option requires superuser priveleges')

        debug.logger & debug.FLAG_IO and debug.logger('enableTransparent: %s option IP_TRANSPARENT on socket %s' % (flag and "enabled" or "disabled", self.socket.fileno()))
        return self

    def sendMessage(self, outgoingMessage, transportAddress):
        self.__outQueue.append(
            (outgoingMessage, self.normalizeAddress(transportAddress))
        )
        debug.logger & debug.FLAG_IO and debug.logger('sendMessage: outgoingMessage queued (%d octets) %s' % (len(outgoingMessage), debug.hexdump(outgoingMessage)))

    def normalizeAddress(self, transportAddress):
        if not isinstance(transportAddress, self.ADDRESS_TYPE):
            transportAddress = self.ADDRESS_TYPE(transportAddress)

        if not transportAddress.getLocalAddress():
            transportAddress.setLocalAddress(self.getLocalAddress())

        return transportAddress

    def getLocalAddress(self):
        # one evil OS does not seem to support getsockname() for DGRAM sockets
        try:
            return self.socket.getsockname()

        except Exception:
            return '0.0.0.0', 0

    # asyncore API
    def handle_connect(self):
        pass

    def writable(self):
        return self.__outQueue

    def handle_write(self):
        outgoingMessage, transportAddress = self.__outQueue.pop(0)
        debug.logger & debug.FLAG_IO and debug.logger('handle_write: transportAddress %r -> %r outgoingMessage (%d octets) %s' % (transportAddress.getLocalAddress(), transportAddress, len(outgoingMessage), debug.hexdump(outgoingMessage)))
        if not transportAddress:
            debug.logger & debug.FLAG_IO and debug.logger('handle_write: missing dst address, loosing outgoing msg')
            return
        try:
            self._sendto(
                self.socket, outgoingMessage, transportAddress
            )
        except socket.error as exc:
            if exc.args[0] in SOCK_ERRORS:
                debug.logger & debug.FLAG_IO and debug.logger('handle_write: ignoring socket error %s' % exc)
            else:
                raise error.CarrierError('sendto() failed for %s: %s' % (transportAddress, exc))

    def readable(self):
        return 1

    def handle_read(self):
        try:
            incomingMessage, transportAddress = self._recvfrom(self.socket, 65535)
            transportAddress = self.normalizeAddress(transportAddress)
            debug.logger & debug.FLAG_IO and debug.logger(
                'handle_read: transportAddress %r -> %r incomingMessage (%d octets) %s' % (transportAddress, transportAddress.getLocalAddress(), len(incomingMessage), debug.hexdump(incomingMessage)))
            if not incomingMessage:
                self.handle_close()
                return
            else:
                self._cbFun(self, transportAddress, incomingMessage)
                return
        except socket.error as exc:
            if exc.args[0] in SOCK_ERRORS:
                debug.logger & debug.FLAG_IO and debug.logger('handle_read: known socket error %s' % exc)
                SOCK_ERRORS[exc.args[0]] and self.handle_close()
                return
            else:
                raise error.CarrierError('recvfrom() failed: %s' % exc)

    def handle_close(self):
        pass  # no datagram connection
