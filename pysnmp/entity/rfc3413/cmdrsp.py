from pysnmp.proto import rfc1157, rfc1905, rfc3411, error
from pysnmp.proto.api import v2c  # backend is always SMIv2 compliant
from pysnmp.proto.proxy import rfc2576
import pysnmp.smi.error

vacmID = 3

# 3.2
class CommandResponderBase:
    pduTypes = ()

    def __init__(self, snmpEngine, snmpContext):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            snmpContext.contextEngineId, self.pduTypes, self.processPdu
            )
        self.snmpContext = snmpContext # for unregistration
        self.__pendingReqs = {}

    def _handleManagementOperation(
        self, snmpEngine, contextMibInstrumCtl, PDU, (acFun, acCtx)
        ): pass
        
    def close(self, snmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(
            self.snmpContext.contextEngineId, self.pduTypes
            )

    def __sendResponse(self, snmpEngine, errorStatus, errorIndex,
                       varBinds, stateReference):
        ( messageProcessingModel,
          securityModel,
          securityName,
          securityLevel,
          contextEngineId,
          contextName,
          pduVersion,
          PDU,
          maxSizeResponseScopedPDU,
          statusInformation ) = self.__pendingReqs[stateReference]

        del self.__pendingReqs[stateReference]

        v2c.apiPDU.setErrorStatus(PDU, errorStatus)
        v2c.apiPDU.setErrorIndex(PDU, errorIndex)
        v2c.apiPDU.setVarBinds(PDU, varBinds)

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v2ToV1(PDU)
        
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
            snmpSilentDrops, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpSilentDrops')
            snmpSilentDrops.syntax = snmpSilentDrops.syntax + 1

    _getRequestType = rfc1905.GetRequestPDU.tagSet
    _getNextRequestType = rfc1905.GetNextRequestPDU.tagSet
    _setRequestType = rfc1905.SetRequestPDU.tagSet
    
    def processPdu(
        self,
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
        stateReference
        ):

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1ToV2(PDU)

        # 3.2.1
        if rfc3411.readClassPDUs.has_key(PDU.tagSet):
            viewType = 'read'
        elif rfc3411.writeClassPDUs.has_key(PDU.tagSet):
            viewType = 'write'
        else:
            raise error.ProtocolError('Unexpected PDU class %s' % PDU.tagSet)
        
        # 3.2.2 --> no-op

        # 3.2.4
        rspPDU = v2c.apiPDU.getResponse(PDU)
        
        statusInformation = {}
        
        self.__pendingReqs[stateReference] = (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            rspPDU,
            maxSizeResponseScopedPDU,
            statusInformation
            )

        contextMibInstrumCtl = self.snmpContext.getMibInstrum(contextName)

        acCtx = (
            snmpEngine, securityModel, securityName, securityLevel, contextName
            )

        # 3.2.5
        varBinds = v2c.apiPDU.getVarBinds(PDU)
        errorStatus, errorIndex = 'noError', 0
        try:
            errorStatus, errorIndex, varBinds = self._handleManagementOperation(
                snmpEngine, contextMibInstrumCtl, PDU,
                (self.__verifyAccess, acCtx)
                )
        # SNMPv2 SMI exceptions
        except pysnmp.smi.error.GenError, errorIndication:
            if errorIndication.has_key('oid'):
                # Request REPORT generation
                statusInformation['oid'] = errorIndication['oid'] 
                statusInformation['val'] = errorIndication['val']

        # PDU-level SMI errors
        except pysnmp.smi.error.NoAccessError, errorIndication:
            errorStatus, errorIndex = 'noAccess', errorIndication['idx'] + 1
        except pysnmp.smi.error.WrongTypeError, errorIndication:
            errorStatus, errorIndex = 'wrongType', errorIndication['idx'] + 1
        except pysnmp.smi.error.WrongValueError, errorIndication:
            errorStatus, errorIndex = 'wrongValue', errorIndication['idx'] + 1
        except pysnmp.smi.error.NoCreationError, errorIndication:
            errorStatus, errorIndex = 'noCreation', errorIndication['idx'] + 1
        except pysnmp.smi.error.InconsistentValueError, errorIndication:
            errorStatus, errorIndex = 'inconsistentValue', errorIndication['idx'] + 1
        except pysnmp.smi.error.ResourceUnavailableError, errorIndication:
            errorStatus, errorIndex = 'resourceUnavailable', errorIndication['idx'] + 1
        except pysnmp.smi.error.CommitFailedError, errorIndication:
            errorStatus, errorIndex = 'commitFailedError', errorIndication['idx'] + 1
        except pysnmp.smi.error.UndoFailedError, errorIndication:
            errorStatus, errorIndex = 'undoFailedError', errorIndication['idx'] + 1
        except pysnmp.smi.error.AuthorizationError, errorIndication:
            errorStatus, errorIndex = 'authorizationError', errorIndication['idx'] + 1
        except pysnmp.smi.error.NotWritableError, errorIndication:
            errorStatus, errorIndex = 'notWritable', errorIndication['idx'] + 1
        except pysnmp.smi.error.InconsistentNameError, errorIndication:
            errorStatus, errorIndex = 'inconsistentName', errorIndication['idx'] + 1
        except pysnmp.smi.error.SmiError, errorIndication:
            errorStatus, errorIndex = 'genErr', 1
            
        self.__sendResponse(
            snmpEngine, errorStatus, errorIndex, varBinds, stateReference
            )

    def __verifyAccess(self, name, idx, viewType,
                       (snmpEngine, securityModel, securityName,
                        securityLevel, contextName)
                       ):
        try:
            snmpEngine.accessControlModel[vacmID].isAccessAllowed(
                snmpEngine, securityModel, securityName,
                securityLevel, viewType, contextName, name
                )
        # Map ACM errors onto SMI ones
        except error.StatusInformation, statusInformation:
            errorIndication = statusInformation['errorIndication']
            # 3.2.5...
            if errorIndication == 'noSuchView' or \
               errorIndication == 'noAccessEntry' or \
               errorIndication == 'noGroupName':
                raise pysnmp.smi.error.AuthorizationError(
                    name=name, idx=idx
                    )
            elif errorIndication == 'otherError':
                raise pysnmp.smi.error.GenError(name=name, idx=idx)
            elif errorIndication == 'noSuchContext':
                snmpUnknownContexts, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-TARGET-MIB', 'snmpUnknownContexts')
                snmpUnknownContexts.syntax = snmpUnknownContexts.syntax + 1
                # Request REPORT generation
                raise pysnmp.smi.error.GenError(
                    name=name, idx=idx,
                    oid=snmpUnknownContexts.name,
                    val=snmpUnknownContexts.syntax
                    )
            elif errorIndication == 'notInView':
                return 1
            else:
                raise error.ProtocolError(
                    'Unknown ACM error %s' % errorIndication
                    )
        
class GetCommandResponder(CommandResponderBase):
    pduTypes = ( rfc1905.GetRequestPDU.tagSet, )

    # rfc1905: 4.2.1
    def _handleManagementOperation(
        self, snmpEngine, contextMibInstrumCtl, PDU, (acFun, acCtx)
        ):
        # rfc1905: 4.2.1.1
        return 0, 0, contextMibInstrumCtl.readVars(
            v2c.apiPDU.getVarBinds(PDU), (acFun, acCtx)
            )

class NextCommandResponder(CommandResponderBase):
    pduTypes = ( rfc1905.GetNextRequestPDU.tagSet, )

    # rfc1905: 4.2.2
    def _handleManagementOperation(self, snmpEngine, contextMibInstrumCtl,
                                   PDU, (acFun, acCtx)):
        # rfc1905: 4.2.1.1
        return 0, 0, contextMibInstrumCtl.readNextVars(
            v2c.apiPDU.getVarBinds(PDU), (acFun, acCtx)
            )

class BulkCommandResponder(CommandResponderBase):
    pduTypes = ( rfc1905.GetBulkRequestPDU.tagSet, )
    maxVarBinds = 64
    
    # rfc1905: 4.2.3
    def _handleManagementOperation(self, snmpEngine, contextMibInstrumCtl,
                                   PDU, (acFun, acCtx)):
        nonRepeaters = v2c.apiBulkPDU.getNonRepeaters(PDU)
        if nonRepeaters < 0:
            nonRepeaters = 0
        maxRepetitions = v2c.apiBulkPDU.getMaxRepetitions(PDU)
        if maxRepetitions < 0:
            maxRepetitions = 0
        reqVarBinds = v2c.apiPDU.getVarBinds(PDU)

        N = min(nonRepeaters, len(reqVarBinds))
        M = int(maxRepetitions)
        R = max(len(reqVarBinds)-N, 0)
        
        if nonRepeaters:
            rspVarBinds = contextMibInstrumCtl.readNextVars(
                reqVarBinds[:int(nonRepeaters)], (acFun, acCtx)
                )
        else:
            rspVarBinds = []

        if M and R:
            for i in range(N,  R):
                varBind = reqVarBinds[i]
                for r in range(1, M):
                    rspVarBinds.extend(contextMibInstrumCtl.readNextVars(
                        (varBind,), (acFun, acCtx)
                        ))
                    varBind = rspVarBinds[-1]

        if len(rspVarBinds) > self.maxVarBinds:
            rspVarBinds = rspVarBinds[:self.maxVarBinds]

        return 0, 0, rspVarBinds

class SetCommandResponder(CommandResponderBase):
    pduTypes = ( rfc1905.SetRequestPDU.tagSet, )

    # rfc1905: 4.2.5
    def _handleManagementOperation(
        self, snmpEngine, contextMibInstrumCtl, PDU, (acFun, acCtx)
        ):
        # rfc1905: 4.2.5.1-13
        try:
            return 0, 0, contextMibInstrumCtl.writeVars(
                v2c.apiPDU.getVarBinds(PDU), (acFun, acCtx)
                )
        except ( pysnmp.smi.error.NoSuchObjectError,
                 pysnmp.smi.error.NoSuchInstanceError ), errorIndication:
            e = pysnmp.smi.error.NotWritableError()
            e.update(errorIndication)
            raise e
