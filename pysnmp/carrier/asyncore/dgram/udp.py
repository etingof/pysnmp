"""Implements asyncore-based UDP transport domain"""
from socket import AF_INET
from types import TupleType, IntType
from string import atoi
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport
from pysnmp.carrier import error

class UdpSocketTransport(DgramSocketTransport):
    sockFamily = AF_INET
    defaultPort = 161

    def rewriteAddress(self, transportAddress):
        if type(transportAddress) == TupleType:
            if type(transportAddress[1]) != IntType:
                try:
                    return transportAddress[0], atoi(transportAddress[1])
                except ValueError, why:
                    raise error.BadArgumentError(
                        'Cant coerce UDP port number %s: %s' %
                        (transportAddress[1], why)
                        )
            else:
                return transportAddress[0], transportAddress[1]
        else:
            return transportAddress, self.defaultPort
