import types, time
from pysnmp.proto import rfc1157, rfc1905, api
from pysnmp.proto import error
from pysnmp.proto.proxy import rfc2576

def getVersionSpecifics(snmpVersion):
    if snmpVersion == 0:
        pduVersion = 0
    else:
        pduVersion = 1
    return pduVersion, api.protoModules[pduVersion]

# XXX move to rfc3413/config
def getTargetInfo(snmpEngine, snmpTargetAddrName):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    snmpTargetAddrEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetAddrEntry'
        )
    tblIdx = snmpTargetAddrEntry.getInstIdFromIndices(
        snmpTargetAddrName
        )
    snmpTargetAddrTDomain = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (2,) + tblIdx
        )
    snmpTargetAddrTAddress = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (3,) + tblIdx
        )
    snmpTargetAddrTimeout = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (4,) + tblIdx
        )
    snmpTargetAddrRetryCount = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (5,) + tblIdx
        )
    snmpTargetAddrParams = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (7,) + tblIdx
        )
    
    # Target params
    snmpTargetParamsEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetParamsEntry'
        )
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(
        snmpTargetAddrParams.syntax
        )
    snmpTargetParamsMPModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (2,) + tblIdx
        )
    snmpTargetParamsSecurityModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (3,) + tblIdx
        )
    snmpTargetParamsSecurityName = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (4,) + tblIdx
        )
    snmpTargetParamsSecurityLevel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (5,) + tblIdx
        )

    return ( snmpTargetAddrTDomain.syntax,
             tuple(snmpTargetAddrTAddress.syntax),
             snmpTargetAddrTimeout.syntax,
             snmpTargetAddrRetryCount.syntax,
             snmpTargetParamsMPModel.syntax,
             snmpTargetParamsSecurityModel.syntax,
             snmpTargetParamsSecurityName.syntax,
             snmpTargetParamsSecurityLevel.syntax )

class CommandGeneratorBase:
    def __init__(self):
        self.__pendingReqs = {}
        self._sendRequestHandleSource = 0L
            
    def processResponsePdu(
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
        statusInformation,
        sendPduHandle,
        (cbFun, cbCtx)
        ):
        # 3.1.1
        ( origTransportDomain,
          origTransportAddress,
          origMessageProcessingModel,
          origSecurityModel,
          origSecurityName,
          origSecurityLevel,
          origContextEngineID,
          origContextName,
          origPduVersion,
          origPdu,
          origTimeout,
          origRetryCount,
          origRetries,
          origSendRequestHandle
          ) = self.__pendingReqs[sendPduHandle]
        del self.__pendingReqs[sendPduHandle]

        snmpEngine.transportDispatcher.jobFinished(id(self))

        # 3.1.3
        if statusInformation:
            if origRetries == origRetryCount:
                cbFun(origSendRequestHandle,
                      statusInformation['errorIndication'], 0, 0, (),
                      cbCtx)
                return
            self._sendPdu(
                snmpEngine,
                origTransportDomain,
                origTransportAddress,
                origMessageProcessingModel,
                origSecurityModel,
                origSecurityName,
                origSecurityLevel,
                origContextEngineID,
                origContextName,
                origPduVersion,
                origPdu,
                origTimeout,
                origRetryCount,
                origRetries,
                origSendRequestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))
                )
            return

        if origMessageProcessingModel != messageProcessingModel or \
           origSecurityModel != securityModel or \
           origSecurityName != origSecurityName or \
           origContextEngineID and origContextEngineID != contextEngineID or \
           origContextName and origContextName != contextName or \
           origPduVersion != pduVersion:
            return

        pMod = api.protoModules[pduVersion]
        
        # 3.1.2
        if pMod.apiPDU.getRequestID(PDU) != pMod.apiPDU.getRequestID(origPdu):
            return

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1ToV2(PDU)
        
        self._handleResponse(
            snmpEngine,
            origTransportDomain,
            origTransportAddress,
            origMessageProcessingModel,
            origSecurityModel,
            origSecurityName,
            origSecurityLevel,
            origContextEngineID,
            origContextName,
            origPduVersion,
            origPdu,
            origTimeout,
            origRetryCount,
            pMod,
            PDU,
            origSendRequestHandle,
            (cbFun, cbCtx),
            )

    def sendReq(
        self,
        snmpEngine,
        addrName,
        varBinds,
        cbFun,
        cbCtx=None,
        contextEngineID=None,
        contextName=''
        ):
        raise error.ProtocolError('Method not implemented')

    def _sendPdu(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        reqPDU,
        timeout,
        retryCount,
        retries,
        sendRequestHandle,
        (processResponsePdu, cbCtx)
        ):    
        # 3.1
        sendPduHandle = snmpEngine.msgAndPduDsp.sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            (processResponsePdu, timeout/1000 + time.time(), cbCtx)
            )

        snmpEngine.transportDispatcher.jobStarted(id(self))

        self.__pendingReqs[sendPduHandle] = (
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            retries + 1,
            sendRequestHandle,
            )

class GetCommandGenerator(CommandGeneratorBase):
    def sendReq(
        self,
        snmpEngine,
        addrName,
        varBinds,
        cbFun,
        cbCtx=None,
        contextEngineID=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.GetRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)
        
        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        self._sendRequestHandleSource = self._sendRequestHandleSource + 1
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return self._sendRequestHandleSource
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        timeout,
        retryCount,
        pMod,
        rspPDU,
        sendRequestHandle,
        (cbFun, cbCtx)
        ):
        cbFun(sendRequestHandle,
              None,
              pMod.apiPDU.getErrorStatus(rspPDU),
              pMod.apiPDU.getErrorIndex(rspPDU),
              pMod.apiPDU.getVarBinds(rspPDU),
              cbCtx)

class SetCommandGenerator(CommandGeneratorBase):
    def sendReq(
        self,
        snmpEngine,
        addrName,
        varBinds,
        cbFun,
        cbCtx=None,
        contextEngineID=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.SetRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)

        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            reqPDU = rfc2576.v2ToV1(reqPDU)
        
        self._sendRequestHandleSource = self._sendRequestHandleSource + 1
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return self._sendRequestHandleSource

    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        timeout,
        retryCount,
        pMod,
        rspPDU,
        sendRequestHandle,
        (cbFun, cbCtx)
        ):
        cbFun(sendRequestHandle,
              None,
              pMod.apiPDU.getErrorStatus(rspPDU),
              pMod.apiPDU.getErrorIndex(rspPDU),
              pMod.apiPDU.getVarBinds(rspPDU),
              cbCtx)

class NextCommandGenerator(CommandGeneratorBase):
    def sendReq(
        self,
        snmpEngine,
        addrName,
        varBinds,
        cbFun,
        cbCtx=None,
        contextEngineID=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.GetNextRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)
        
        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        self._sendRequestHandleSource = self._sendRequestHandleSource + 1
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return self._sendRequestHandleSource
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        timeout,
        retryCount,
        pMod,
        rspPDU,
        sendRequestHandle,
        (cbFun, cbCtx)
        ):
        varBindTable = pMod.apiPDU.getVarBindTable(PDU, rspPDU)

        if not cbFun(sendRequestHandle, None,
                     pMod.apiPDU.getErrorStatus(rspPDU),
                     pMod.apiPDU.getErrorIndex(rspPDU),
                     varBindTable, cbCtx):
            return  # app says enough
        
        pMod.apiPDU.setRequestID(PDU, pMod.getNextRequestID())
        pMod.apiPDU.setVarBinds(
            PDU, map(lambda (x,y),n=pMod.Null(): (x,n), varBindTable[-1])
            )

        self._sendRequestHandleSource = self._sendRequestHandleSource + 1

        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            PDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

class BulkCommandGenerator(CommandGeneratorBase):
    def sendReq(
        self,
        snmpEngine,
        addrName,
        nonRepeaters,
        maxRepetitions,
        varBinds,
        cbFun,
        cbCtx=None,
        contextEngineID=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.GetBulkRequestPDU()
        
        pMod.apiBulkPDU.setNonRepeaters(reqPDU, nonRepeaters)
        pMod.apiBulkPDU.setMaxRepetitions(reqPDU, maxRepetitions)
        
        pMod.apiBulkPDU.setDefaults(reqPDU)
        
        pMod.apiBulkPDU.setVarBinds(reqPDU, varBinds)

        self._sendRequestHandleSource = self._sendRequestHandleSource + 1
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return self._sendRequestHandleSource
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineID,
        contextName,
        pduVersion,
        PDU,
        timeout,
        retryCount,
        pMod,
        rspPDU,
        sendRequestHandle,
        (cbFun, cbCtx)
        ):
        varBindTable = pMod.apiBulkPDU.getVarBindTable(PDU, rspPDU)
            
        if not cbFun(sendRequestHandle, None,
                     pMod.apiBulkPDU.getErrorStatus(rspPDU),
                     pMod.apiBulkPDU.getErrorIndex(rspPDU),
                     varBindTable, cbCtx):
            return # app says enough

        pMod.apiBulkPDU.setRequestID(PDU, pMod.getNextRequestID())
        pMod.apiBulkPDU.setVarBinds(
            PDU, map(lambda (x,y),n=pMod.Null(): (x,n), varBindTable[-1])
            )

        self._sendRequestHandleSource = self._sendRequestHandleSource + 1
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineID,
            contextName,
            pduVersion,
            PDU,
            timeout,
            retryCount,
            0,
            self._sendRequestHandleSource,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )
