#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from time import time

from pysnmp.proto.api import verdec
from pysnmp.proto import api
from pysnmp.proto import error
from pysnmp import debug

from pyasn1.codec.ber import encoder, decoder

__all__ = []


class AbstractSnmpDispatcher(object):
    """Creates SNMP message dispatcher object.

    `SnmpDispatcher` object manages send and receives SNMP PDU
    messages through underlying transport dispatcher and dispatches
    them to the callers.

    `SnmpDispatcher` is the only stateful object, all `hlapi.v1arch` SNMP
    operations require an instance of `SnmpDispatcher`. Users do not normally
    request services directly from `SnmpDispather`, but pass it around to
    other `hlapi.v1arch` interfaces.

    It is possible to run multiple instances of `SnmpDispatcher` in the
    application. In a multithreaded environment, each thread that
    works with SNMP must have its own `SnmpDispatcher` instance.
    """

    PROTO_DISPATCHER = None

    def __init__(self, transportDispatcher=None):
        if transportDispatcher:
            self.transportDispatcher = transportDispatcher

        else:
            self.transportDispatcher = self.PROTO_DISPATCHER()

        self._automaticDispatcher = transportDispatcher is not self.transportDispatcher
        self._configuredTransports = set()

        self._pendingReqs = {}

        self.transportDispatcher.registerRecvCbFun(self._recvCb)
        self.transportDispatcher.registerTimerCbFun(self._timerCb)

        self.cache = {}

    def __repr__(self):
        return '%s(transportDispatcher=%s)' % (self.__class__.__name__, self.transportDispatcher)

    def close(self):
        self.transportDispatcher.unregisterRecvCbFun()
        self.transportDispatcher.unregisterTimerCbFun()
        if self._automaticDispatcher:
            self.transportDispatcher.close()

        for requestId, stateInfo in self._pendingReqs.items():
            cbFun = stateInfo['cbFun']
            cbCtx = stateInfo['cbCtx']

            if cbFun:
                cbFun(self, 'Request #%d terminated' % requestId, None, cbCtx)

        self._pendingReqs.clear()

    def sendPdu(self, authData, transportTarget, reqPdu, cbFun=None, cbCtx=None):
        if (self._automaticDispatcher and
                transportTarget.transportDomain not in self._configuredTransports):
            self.transportDispatcher.registerTransport(
                transportTarget.transportDomain, transportTarget.protoTransport().openClientMode()
            )
            self._configuredTransports.add(transportTarget.transportDomain)

        pMod = api.PROTOCOL_MODULES[authData.mpModel]

        reqMsg = pMod.Message()
        pMod.apiMessage.setDefaults(reqMsg)
        pMod.apiMessage.setCommunity(reqMsg, authData.communityName)
        pMod.apiMessage.setPDU(reqMsg, reqPdu)

        outgoingMsg = encoder.encode(reqMsg)

        requestId = pMod.apiPDU.getRequestID(reqPdu)

        self._pendingReqs[requestId] = dict(
            outgoingMsg=outgoingMsg,
            transportTarget=transportTarget,
            cbFun=cbFun, cbCtx=cbCtx,
            timestamp=time() + transportTarget.timeout, retries=0
        )

        self.transportDispatcher.sendMessage(
            outgoingMsg, transportTarget.transportDomain, transportTarget.transportAddr
        )

        if (reqPdu.__class__ is getattr(pMod, 'SNMPv2TrapPDU', None) or
                reqPdu.__class__ is getattr(pMod, 'TrapPDU', None)):
            return requestId

        self.transportDispatcher.jobStarted(id(self))

        return requestId

    def _recvCb(self, snmpEngine, transportDomain, transportAddress, wholeMsg):
        try:
            mpModel = verdec.decodeMessageVersion(wholeMsg)

        except error.ProtocolError:
            return null  # n.b the whole buffer gets dropped

        debug.logger & debug.FLAG_DSP and debug.logger('receiveMessage: msgVersion %s, msg decoded' % mpModel)

        pMod = api.PROTOCOL_MODULES[mpModel]

        while wholeMsg:
            rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
            rspPdu = pMod.apiMessage.getPDU(rspMsg)

            requestId = pMod.apiPDU.getRequestID(rspPdu)

            try:
                stateInfo = self._pendingReqs.pop(requestId)

            except KeyError:
                continue

            self.transportDispatcher.jobFinished(id(self))

            cbFun = stateInfo['cbFun']
            cbCtx = stateInfo['cbCtx']

            if cbFun:
                cbFun(self, requestId, None, rspPdu, cbCtx)

        return wholeMsg

    def _timerCb(self, timeNow):
        for requestId, stateInfo in tuple(self._pendingReqs.items()):
            if stateInfo['timestamp'] > timeNow:
                continue

            retries = stateInfo['retries']
            transportTarget = stateInfo['transportTarget']

            if retries == transportTarget.retries:
                cbFun = stateInfo['cbFun']
                cbCtx = stateInfo['cbCtx']

                if cbFun:
                    del self._pendingReqs[requestId]
                    cbFun(self, requestId, 'Request #%d timed out' % requestId, None, cbCtx)
                    self.transportDispatcher.jobFinished(id(self))
                    continue

            stateInfo['retries'] += 1
            stateInfo['timestamp'] = timeNow + transportTarget.timeout

            outgoingMsg = stateInfo['outgoingMsg']

            self.transportDispatcher.sendMessage(
                outgoingMsg, transportTarget.transportDomain, transportTarget.transportAddr
            )
