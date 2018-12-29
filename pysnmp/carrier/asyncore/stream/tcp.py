#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# Author: Edgar Sousa <edg@edgsousa.xyz>
#
from socket import AF_INET

from pysnmp.carrier.asyncore.stream.base import StreamSocketTransport
from pysnmp.carrier.base import AbstractTransportAddress

domainName = snmpTCPDomain = (1, 3, 6, 1, 2, 1, 100, 1, 5)


class TcpTransportAddress(tuple, AbstractTransportAddress):
    pass


class TcpSocketTransport(StreamSocketTransport):
    sockFamily = AF_INET
    addressType = TcpTransportAddress
