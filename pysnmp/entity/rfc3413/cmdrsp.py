#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys
from pysnmp.proto import rfc1902, rfc1905, rfc3411, errind, error
from pysnmp.proto.api import v2c  # backend is always SMIv2 compliant
from pysnmp.proto.proxy import rfc2576
import pysnmp.smi.error
from pysnmp import debug


# 3.2
class CommandResponderBase(object):
    acmID = 3  # default MIB access control method to use
    SUPPORTED_PDU_TYPES = ()
    SMI_ERROR_MAP = {
        pysnmp.smi.error.NoAccessError: 'noAccess',
        pysnmp.smi.error.WrongTypeError: 'wrongType',
        pysnmp.smi.error.WrongLengthError: 'wrongLength',
        pysnmp.smi.error.WrongEncodingError: 'wrongEncoding',
        pysnmp.smi.error.WrongValueError: 'wrongValue',
        pysnmp.smi.error.NoCreationError: 'noCreation',
        pysnmp.smi.error.InconsistentValueError: 'inconsistentValue',
        pysnmp.smi.error.ResourceUnavailableError: 'resourceUnavailable',
        pysnmp.smi.error.CommitFailedError: 'commitFailed',
        pysnmp.smi.error.UndoFailedError: 'undoFailed',
        pysnmp.smi.error.AuthorizationError: 'authorizationError',
        pysnmp.smi.error.NotWritableError: 'notWritable',
        pysnmp.smi.error.InconsistentNameError: 'inconsistentName'
    }

    def __init__(self, snmpEngine, snmpContext, cbCtx=None):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            snmpContext.contextEngineId, self.SUPPORTED_PDU_TYPES, self.processPdu
        )
        self.snmpContext = snmpContext
        self.cbCtx = cbCtx
        self.__pendingReqs = {}

    def close(self, snmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(
            self.snmpContext.contextEngineId, self.SUPPORTED_PDU_TYPES
        )
        self.snmpContext = self.__pendingReqs = None

    def releaseStateInformation(self, stateReference):
        if stateReference in self.__pendingReqs:
            del self.__pendingReqs[stateReference]

    def sendVarBinds(self, snmpEngine, stateReference,
                     errorStatus, errorIndex, varBinds):
        (messageProcessingModel,
         securityModel,
         securityName,
         securityLevel,
         contextEngineId,
         contextName,
         pduVersion,
         PDU,
         origPdu,
         maxSizeResponseScopedPDU,
         statusInformation) = self.__pendingReqs[stateReference]

        v2c.apiPDU.setErrorStatus(PDU, errorStatus)
        v2c.apiPDU.setErrorIndex(PDU, errorIndex)
        v2c.apiPDU.setVarBinds(PDU, varBinds)

        debug.logger & debug.flagApp and debug.logger(
            'sendVarBinds: stateReference %s, errorStatus %s, errorIndex %s, varBinds %s' % (
            stateReference, errorStatus, errorIndex, varBinds)
        )

        self.sendPdu(snmpEngine, stateReference, PDU)

    def sendPdu(self, snmpEngine, stateReference, PDU):
        (messageProcessingModel,
         securityModel,
         securityName,
         securityLevel,
         contextEngineId,
         contextName,
         pduVersion,
         _,
         origPdu,
         maxSizeResponseScopedPDU,
         statusInformation) = self.__pendingReqs[stateReference]

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v2ToV1(PDU, origPdu)

        # 3.2.6
        try:
            snmpEngine.msgAndPduDsp.returnResponsePdu(
                snmpEngine,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pduVersion,
                PDU,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation
            )

        except error.StatusInformation:
            debug.logger & debug.flagApp and debug.logger(
                'sendPdu: stateReference %s, statusInformation %s' % (stateReference, sys.exc_info()[1]))
            snmpSilentDrops, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB',
                                                                                                     'snmpSilentDrops')
            snmpSilentDrops.syntax += 1

    _getRequestType = rfc1905.GetRequestPDU.tagSet
    _getNextRequestType = rfc1905.GetNextRequestPDU.tagSet
    _setRequestType = rfc1905.SetRequestPDU.tagSet
    _counter64Type = rfc1902.Counter64.tagSet

    def processPdu(self, snmpEngine, messageProcessingModel, securityModel,
                   securityName, securityLevel, contextEngineId, contextName,
                   pduVersion, PDU, maxSizeResponseScopedPDU, stateReference):

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            origPdu = PDU
            PDU = rfc2576.v1ToV2(PDU)
        else:
            origPdu = None

        # 3.2.1
        if (PDU.tagSet not in rfc3411.readClassPDUs and
                PDU.tagSet not in rfc3411.writeClassPDUs):
            raise error.ProtocolError('Unexpected PDU class %s' % PDU.tagSet)

        # 3.2.2 --> no-op

        # 3.2.4
        rspPDU = v2c.apiPDU.getResponse(PDU)

        statusInformation = {}

        self.__pendingReqs[stateReference] = (
            messageProcessingModel, securityModel, securityName,
            securityLevel, contextEngineId, contextName, pduVersion,
            rspPDU, origPdu, maxSizeResponseScopedPDU, statusInformation
        )

        # 3.2.5
        varBinds = v2c.apiPDU.getVarBinds(PDU)

        debug.logger & debug.flagApp and debug.logger(
            'processPdu: stateReference %s, varBinds %s' % (stateReference, varBinds))

        self.initiateMgmtOperation(snmpEngine, stateReference, contextName, PDU)

    @classmethod
    def verifyAccess(cls, viewType, varBind, **context):
        name, val = varBind

        snmpEngine = context['snmpEngine']

        execCtx = snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage:request')
        (securityModel,
         securityName,
         securityLevel,
         contextName,
         pduType) = (execCtx['securityModel'],
                     execCtx['securityName'],
                     execCtx['securityLevel'],
                     execCtx['contextName'],
                     execCtx['pdu'].getTagSet())

        try:
            snmpEngine.accessControlModel[cls.acmID].isAccessAllowed(
                snmpEngine, securityModel, securityName,
                securityLevel, viewType, contextName, name
            )

        # Map ACM errors onto SMI ones
        except error.StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger(
                '__verifyAccess: name %s, statusInformation %s' % (name, statusInformation))
            errorIndication = statusInformation['errorIndication']
            # 3.2.5...
            if (errorIndication == errind.noSuchView or
                    errorIndication == errind.noAccessEntry or
                    errorIndication == errind.noGroupName):
                raise pysnmp.smi.error.AuthorizationError(name=name, idx=context.get('idx'))

            elif errorIndication == errind.otherError:
                raise pysnmp.smi.error.GenError(name=name, idx=context.get('idx'))

            elif errorIndication == errind.noSuchContext:
                snmpUnknownContexts, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
                    '__SNMP-TARGET-MIB', 'snmpUnknownContexts')
                snmpUnknownContexts.syntax += 1
                # Request REPORT generation
                raise pysnmp.smi.error.GenError(name=name, idx=context.get('idx'),
                                                oid=snmpUnknownContexts.name,
                                                val=snmpUnknownContexts.syntax)

            elif errorIndication == errind.notInView:
                return True

            else:
                raise error.ProtocolError('Unknown ACM error %s' % errorIndication)
        else:
            # rfc2576: 4.1.2.1
            if (securityModel == 1 and val is not None and
                    cls._counter64Type == val.getTagSet() and
                    cls._getNextRequestType == pduType):
                # This will cause MibTree to skip this OID-value
                raise pysnmp.smi.error.NoAccessError(name=name, idx=context.get('idx'))

    def _getMgmtFun(self, contextName):
        return lambda *args, **kwargs: None

    def _checkSmiErrors(self, varBinds):
        errorIndication = None
        errorStatus = errorIndex = 0

        exception = None

        for idx, varBind in enumerate(varBinds):
            name, value = varBind
            if isinstance(value, tuple):  # expect exception tuple
                debug.logger & debug.flagApp and debug.logger(
                    '_checkSmiErrors: exception reported for OID %s exception %s' % (name, value))

                if not exception:
                    exception = value

                # reset exception object
                varBinds[idx] = name, v2c.null

        try:
            # TODO: perhaps chain exceptions
            if exception:
                debug.logger & debug.flagApp and debug.logger(
                    '_checkSmiErrors: re-raising exception %s' % (exception,))
                raise exception[1].with_traceback(exception[2])

        # SNMPv2 SMI exceptions
        except pysnmp.smi.error.GenError:
            errorIndication = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger(
                '_checkSmiErrors: errorIndication %s' % (errorIndication,))

        except pysnmp.smi.error.SmiError:
            exc_type, exc_obj, trb = sys.exc_info()

            errorStatus = self.SMI_ERROR_MAP.get(exc_type, 'genErr')

            try:
                errorIndex = exc_obj['idx'] + 1

            except IndexError:
                errorIndex = len(varBinds) and 1 or 0

        return errorIndication, errorStatus, errorIndex

    def completeMgmtOperation(self, varBinds, **context):

        try:
            (errorIndication,
             errorStatus, errorIndex) = self._checkSmiErrors(varBinds)

        except pysnmp.error.PySnmpError:
            self.releaseStateInformation(context['stateReference'])
            return

        stateReference = context['stateReference']

        if errorIndication:
            statusInformation = self.__pendingReqs[stateReference]['statusInformation']

            try:
                # Request REPORT generation
                statusInformation['oid'] = errorIndication['oid']
                statusInformation['val'] = errorIndication['val']

            except KeyError:
                pass

        self.sendVarBinds(context['snmpEngine'], stateReference,
                          errorStatus, errorIndex, varBinds)

        self.releaseStateInformation(stateReference)

    def initiateMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        varBinds = v2c.apiPDU.getVarBinds(PDU)

        mgmtFun = self._getMgmtFun(contextName)

        context = dict(snmpEngine=snmpEngine,
                       stateReference=stateReference,
                       acFun=self.verifyAccess,
                       cbFun=self.completeMgmtOperation,
                       cbCtx=self.cbCtx)

        mgmtFun(*varBinds, **context)


class GetCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetRequestPDU.tagSet,)

    # rfc1905: 4.2.1
    def _getMgmtFun(self, contextName):
        return self.snmpContext.getMibInstrum(contextName).readVars


class NextCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetNextRequestPDU.tagSet,)

    # rfc1905: 4.2.2
    def _getMgmtFun(self, contextName):
        return self.snmpContext.getMibInstrum(contextName).readNextVars


class BulkCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.GetBulkRequestPDU.tagSet,)
    maxVarBinds = 64

    def _getMgmtFun(self, contextName):
        return self.snmpContext.getMibInstrum(contextName).readNextVars

    def _completeNonRepeaters(self, varBinds, **context):
        context['rspVarBinds'][:] = varBinds

        if context['counters']['M'] and context['counters']['R']:
            context['cbFun'] = self.completeMgmtOperation

            mgmtFun = self._getMgmtFun(context['contextName'])

            mgmtFun(*context['reqVarBinds'], **context)

        else:
            CommandResponderBase.completeMgmtOperation(self, context['rspVarBinds'], **context)

    def completeMgmtOperation(self, varBinds, **context):
        context['rspVarBinds'].extend(varBinds)
        context['counters']['M'] -= 1

        if context['counters']['M'] and context['counters']['R']:
            mgmtFun = self._getMgmtFun(context['contextName'])

            context['cbFun'] = self.completeMgmtOperation
            mgmtFun(*varBinds[-context['counters']['R']:], **context)

        else:
            CommandResponderBase.completeMgmtOperation(self, context['rspVarBinds'], **context)

    # rfc1905: 4.2.3
    def initiateMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        nonRepeaters = v2c.apiBulkPDU.getNonRepeaters(PDU)
        if nonRepeaters < 0:
            nonRepeaters = 0

        maxRepetitions = v2c.apiBulkPDU.getMaxRepetitions(PDU)
        if maxRepetitions < 0:
            maxRepetitions = 0

        varBinds = v2c.apiPDU.getVarBinds(PDU)

        N = min(int(nonRepeaters), len(varBinds))
        M = int(maxRepetitions)
        R = max(len(varBinds) - N, 0)

        if R:
            M = min(M, self.maxVarBinds // R)

        debug.logger & debug.flagApp and debug.logger(
            'initiateMgmtOperation: N %d, M %d, R %d' % (N, M, R))

        mgmtFun = self._getMgmtFun(contextName)

        context = dict(snmpEngine=snmpEngine,
                       stateReference=stateReference,
                       contextName=contextName,
                       acFun=self.verifyAccess,
                       cbFun=self._completeNonRepeaters,
                       cbCtx=self.cbCtx,
                       reqVarBinds=varBinds[N:],
                       counters={'M': M, 'R': R},
                       rspVarBinds=[])

        mgmtFun(*varBinds[:N], **context)


class SetCommandResponder(CommandResponderBase):
    SUPPORTED_PDU_TYPES = (rfc1905.SetRequestPDU.tagSet,)

    SMI_ERROR_MAP = CommandResponderBase.SMI_ERROR_MAP.copy()

    # turn missing OIDs into access denial
    SMI_ERROR_MAP[pysnmp.smi.error.NoSuchObjectError] = 'notWritable'
    SMI_ERROR_MAP[pysnmp.smi.error.NoSuchInstanceError] = 'notWritable'

    # rfc1905: 4.2.5.1-13
    def _getMgmtFun(self, contextName):
        return self.snmpContext.getMibInstrum(contextName).writeVars
