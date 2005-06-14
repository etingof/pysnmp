from pysnmp.proto import rfc1157, rfc1905, api
from pysnmp.proto import rfc1905, rfc3411, error
import pysnmp.smi.error

vacmID = 3

# 3.2
class CmdRspBase:
    pduTypes = ()

    def __init__(self, snmpEngine, contextEngineId=None):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            contextEngineId, self.pduTypes, self.processPdu
            )
        self.__contextEngineId = contextEngineId # for unregistration
        self.__pendingReqs = {}
        self.__contextNames = {}

    def registerContextName(self, contextName, mibInstrumController):
        if self.__contextNames.has_key(contextName):
            raise error.ProtocolError(
                'Duplicate contextNames %s' % contextName
                )
        self.__contextNames[contextName] = mibInstrumController

    def unregisterContextName(self, contextName):
        if not self.__contextNames.has_key(contextName):
            raise error.ProtocolError(
                'No such contextName %s' % contextName
                )
        del self.__contextNames[contextName]
        
    def close(self, snmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(
            self.__contextEngineId, self.pduTypes
            )

    def __sendResponse(self, snmpEngine, errorStatus, errorIndex,
                       varBinds, stateReference):
        ( messageProcessingModel,
          securityModel,
          securityName,
          securityLevel,
          contextEngineID,
          contextName,
          pduVersion,
          PDU,
          maxSizeResponseScopedPDU,
          statusInformation ) = self.__pendingReqs[stateReference]

        del self.__pendingReqs[stateReference]

        pMod = api.protoModules[pduVersion]

        pMod.apiPDU.setErrorStatus(PDU, errorStatus)
        pMod.apiPDU.setErrorIndex(PDU, errorIndex)
        pMod.apiPDU.setVarBinds(PDU, varBinds)

        # 3.2.6
        try:
            snmpEngine.msgAndPduDsp.returnResponsePdu(
                snmpEngine,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineID,
                contextName,
                pduVersion,
                PDU,
                maxSizeResponseScopedPDU,
                stateReference,
                statusInformation
                )
        except error.StatusInformation:
            snmpSilentDrops, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-MIB', 'snmpSilentDrops')
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
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        maxSizeResponseScopedPDU,
        stateReference
        ):
        pMod = api.protoModules[pduVersion]

        # 3.2.1
        if rfc3411.readClassPDUs.has_key(PDU.tagSet):
            viewType = 'read'
        elif rfc3411.writeClassPDUs.has_key(PDU.tagSet):
            viewType = 'write'
        else:
            raise error.ProtocolError('Unexpected PDU class %s' % PDU.tagSet)
        
        # 3.2.2
        requestId = pMod.apiPDU.getRequestID(PDU)

        # 3.2.4
        rspPDU = pMod.apiPDU.getResponse(PDU)

        statusInformation = {}
        
        self.__pendingReqs[stateReference] = (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            rspPDU,
            maxSizeResponseScopedPDU,
            statusInformation
            )

        if self.__contextNames.has_key(str(contextName)):
            contextMibInstrumCtl =  self.__contextNames[contextName]
        else:
            contextMibInstrumCtl = snmpEngine.msgAndPduDsp.mibInstrumController

        acCtx = (
            snmpEngine, securityModel, securityName, securityLevel, contextName
            )
            
        # 3.2.5
        varBinds = pMod.apiPDU.getVarBinds(PDU)
        errorStatus, errorIndex = 'noError', 0
        try:
            errorStatus, errorIndex, varBinds = self._handleManagementOperation(
                snmpEngine, contextMibInstrumCtl, pMod, PDU,
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
            errorStatus, errorIndex = 'noAccess', errorIndication['idx']
        except pysnmp.smi.error.WrongTypeError, errorIndication:
            errorStatus, errorIndex = 'wrongType', errorIndication['idx']
        except pysnmp.smi.error.WrongValueError, errorIndication:
            errorStatus, errorIndex = 'wrongValue', errorIndication['idx']
        except pysnmp.smi.error.NoCreationError, errorIndication:
            errorStatus, errorIndex = 'noCreation', errorIndication['idx']
        except pysnmp.smi.error.InconsistentValueError, errorIndication:
            errorStatus, errorIndex = 'inconsistentValue', errorIndication['idx']
        except pysnmp.smi.error.ResourceUnavailableError, errorIndication:
            errorStatus, errorIndex = 'resourceUnavailable', errorIndication['idx']
        except pysnmp.smi.error.CommitFailedError, errorIndication:
            errorStatus, errorIndex = 'commitFailedError', errorIndication['idx']
        except pysnmp.smi.error.UndoFailedError, errorIndication:
            errorStatus, errorIndex = 'undoFailedError', errorIndication['idx']
        except pysnmp.smi.error.AuthorizationError, errorIndication:
            errorStatus, errorIndex = 'authorizationError', errorIndication['idx']
        except pysnmp.smi.error.NotWritableError, errorIndication:
            errorStatus, errorIndex = 'notWritable', errorIndication['idx']
        except pysnmp.smi.error.InconsistentNameError, errorIndication:
            errorStatus, errorIndex = 'inconsistentName', errorIndication['idx']
        except pysnmp.smi.error.SmiError, errorIndication:
            errorStatus, errorIndex = 'genErr', errorIndication['idx']
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
            if errorIndication == 'noSuchView' or \
               errorIndication == 'noAccessEntry' or \
               errorIndication == 'noGroupName':
                raise pysnmp.smi.error.AuthorizationError(
                    name=name, idx=idx
                    )
            elif errorIndication == 'otherError':
                raise pysnmp.smi.error.GenError(name=name, idx=idx)
            elif errorIndication == 'noSuchContext':
                snmpUnknownContexts, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpUnknownContexts')
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
        
class GetRsp(CmdRspBase):
    pduTypes = ( rfc1905.GetRequestPDU.tagSet, )

    # rfc1905: 4.2.1
    def _handleManagementOperation(
        self, snmpEngine, contextMibInstrumCtl, pMod, PDU, (acFun, acCtx)
        ):
        # rfc1905: 4.2.1.1
        return 0, 0, contextMibInstrumCtl.readVars(
            pMod.apiPDU.getVarBinds(PDU), (acFun, acCtx)
            )

class GetNextRsp(CmdRspBase):
    pduTypes = ( rfc1905.GetNextRequestPDU.tagSet, )

    # rfc1905: 4.2.2
    def _handleManagementOperation(self, snmpEngine, contextMibInstrumCtl,
                                   pMod, PDU, (acFun, acCtx)):
        # rfc1905: 4.2.1.1
        return 0, 0, contextMibInstrumCtl.readNextVars(
            pMod.apiPDU.getVarBinds(PDU), (acFun, acCtx)
            )

class GetBulkRsp(CmdRspBase):
    pduTypes = ( rfc1905.GetBulkRequestPDU.tagSet, )
    maxVarBinds = 64
    
    # rfc1905: 4.2.3
    def _handleManagementOperation(self, snmpEngine, contextMibInstrumCtl,
                                   pMod, PDU, (acFun, acCtx)):
        nonRepeaters = pMod.apiBulkPDU.getNonRepeaters(PDU)
        if nonRepeaters < 0:
            nonRepeaters = 0
        maxRepetitions = pMod.apiBulkPDU.getMaxRepetitions(PDU)
        if maxRepetitions < 0:
            maxRepetitions = 0
        reqVarBinds = pMod.apiPDU.getVarBinds(PDU)

        N = min(nonRepeaters, len(reqVarBinds))
        M = int(maxRepetitions)
        R = max(len(reqVarBinds)-N, 0)
        
        if nonRepeaters:
            rspVarBinds = contextMibInstrumCtl.readNextVars(
                reqVarBinds[:nonRepeaters], (acFun, acCtx)
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
    
# XXX
# invoke shutdown methods
# pysnmp-mib should be no-accessible
# re-work mibinstrum for return through cb fun (async mode) ?
# how to pass name/index with RowStatus exception
# persistent objects (key)
# each managed object should be able to access others through mibBuilder
# cleanup caches
# rework linear search behind the acl
# move mib view out of manager apps
# implement one-liners
