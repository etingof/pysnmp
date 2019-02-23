#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.compat.octets import null

from pysnmp import error
from pysnmp.carrier.base import AbstractTransport

__all__ = []


class AbstractTransportTarget(object):
    TRANSPORT_DOMAIN = None
    PROTO_TRANSPORT = AbstractTransport

    def __init__(self, transportAddr, timeout=1, retries=5, tagList=null):
        self.transportAddr = self._resolveAddr(transportAddr)
        self.timeout = timeout
        self.retries = retries
        self.tagList = tagList
        self.iface = None
        self.transport = None

    def __repr__(self):
        return '%s(%r, timeout=%r, retries=%r, tagList=%r)' % (
            self.__class__.__name__, self.transportAddr,
            self.timeout, self.retries, self.tagList)

    def getTransportInfo(self):
        return self.TRANSPORT_DOMAIN, self.transportAddr

    def setLocalAddress(self, iface):
        """Set source address.

        Parameters
        ----------
        iface : tuple
            Indicates network address of a local interface from which SNMP packets will be originated.
            Format is the same as of `transportAddress`.

        Returns
        -------
            self

        """
        self.iface = iface
        return self

    def openClientMode(self):
        self.transport = self.PROTO_TRANSPORT().openClientMode(self.iface)
        return self.transport

    def verifyDispatcherCompatibility(self, snmpEngine):
        if not self.PROTO_TRANSPORT.isCompatibleWithDispatcher(
                snmpEngine.transportDispatcher):
            raise error.PySnmpError(
                'Transport %r is not compatible with dispatcher '
                '%r' % (self.PROTO_TRANSPORT, snmpEngine.transportDispatcher))

    def _resolveAddr(self, transportAddr):
        raise NotImplementedError()
