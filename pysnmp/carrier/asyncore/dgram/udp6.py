#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import socket

from pysnmp.carrier.asyncore.dgram.base import DgramSocketTransport
from pysnmp.carrier.base import AbstractTransportAddress

DOMAIN_NAME = SNMP_UDP6_DOMAIN = (1, 3, 6, 1, 2, 1, 100, 1, 2)


class Udp6TransportAddress(tuple, AbstractTransportAddress):
    pass


class Udp6SocketTransport(DgramSocketTransport):
    SOCK_FAMILY = socket.has_ipv6 and socket.AF_INET6 or None
    ADDRESS_TYPE = Udp6TransportAddress

    def normalizeAddress(self, transportAddress):
        if '%' in transportAddress[0]:  # strip zone ID
            ta = self.ADDRESS_TYPE(
                (transportAddress[0].split('%')[0], transportAddress[1], 0, 0))

        else:
            ta = self.ADDRESS_TYPE(
                (transportAddress[0], transportAddress[1], 0, 0))

        if (isinstance(transportAddress, self.ADDRESS_TYPE) and
                transportAddress.getLocalAddress()):

            return ta.setLocalAddress(transportAddress.getLocalAddress())

        else:
            return ta.setLocalAddress(self.getLocalAddress())


Udp6Transport = Udp6SocketTransport
