import types, time
from pysnmp.proto import rfc1157, rfc1905, api
from pysnmp.entity.rfc3413 import config
from pysnmp.proto.proxy import rfc2576
from pysnmp.proto import error
from pysnmp import nextid

getNextHandle = nextid.Integer(0x7fffffff)
                             
def getVersionSpecifics(snmpVersion):
    if snmpVersion == 0:
        pduVersion = 0
    else:
        pduVersion = 1
    return pduVersion, api.protoModules[pduVersion]

class CommandGeneratorBase:
    def __init__(self):
        self.__pendingReqs = {}
            
    def processResponsePdu(
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
          origContextEngineId,
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
                origContextEngineId,
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
           origContextEngineId and origContextEngineId != contextEngineId or \
           origContextName and origContextName != contextName or \
           origPduVersion != pduVersion:
            return

        pMod = api.protoModules[pduVersion]
        
        # 3.1.2
        if pMod.apiPDU.getRequestID(PDU) != pMod.apiPDU.getRequestID(origPdu):
            return

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1ToV2(PDU, origPdu)
            pMod = api.protoModules[api.protoVersion2c]
        
        self._handleResponse(
            snmpEngine,
            origTransportDomain,
            origTransportAddress,
            origMessageProcessingModel,
            origSecurityModel,
            origSecurityName,
            origSecurityLevel,
            origContextEngineId,
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
        contextEngineId=None,
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
        contextEngineId,
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
            contextEngineId,
            contextName,
            pduVersion,
            reqPDU,
            (processResponsePdu, float(timeout)/100 + time.time(), cbCtx)
            )

        snmpEngine.transportDispatcher.jobStarted(id(self))

        self.__pendingReqs[sendPduHandle] = (
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
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
        contextEngineId=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = config.getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.GetRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)
        
        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            requestHandle,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return requestHandle
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
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
        contextEngineId=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = config.getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.SetRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)

        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            reqPDU = rfc2576.v2ToV1(reqPDU)
            pMod = api.protoModules[api.protoVersion1]

        requestHandle = getNextHandle()        
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            requestHandle,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return requestHandle

    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
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
        contextEngineId=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = config.getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
        
        reqPDU = pMod.GetNextRequestPDU()
        pMod.apiPDU.setDefaults(reqPDU)
        
        pMod.apiPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()        
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            requestHandle,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return requestHandle
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
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
            PDU, map(lambda (x,y),n=pMod.Null(''): (x,n), varBindTable[-1])
            )

        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            PDU,
            timeout,
            retryCount,
            0,
            getNextHandle(),
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
        contextEngineId=None,
        contextName=''
        ):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = config.getTargetInfo(snmpEngine, addrName)

        pduVersion, pMod = getVersionSpecifics(messageProcessingModel)
       
        if not hasattr(pMod, 'GetBulkRequestPDU'):
            raise error.ProtocolError('BULK PDU not implemented at %s' % pMod)
        reqPDU = pMod.GetBulkRequestPDU()
        pMod.apiBulkPDU.setDefaults(reqPDU)
        
        pMod.apiBulkPDU.setNonRepeaters(reqPDU, nonRepeaters)
        pMod.apiBulkPDU.setMaxRepetitions(reqPDU, maxRepetitions)

        pMod.apiBulkPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()        
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            reqPDU,
            timeout,
            retryCount,
            0,
            requestHandle,
            (self.processResponsePdu, (cbFun, cbCtx))            
            )

        return requestHandle
    
    def _handleResponse(
        self,
        snmpEngine,
        transportDomain,
        transportAddress,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
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
            PDU, map(lambda (x,y),n=pMod.Null(''): (x,n), varBindTable[-1])
            )
        
        self._sendPdu(
            snmpEngine,
            transportDomain,
            transportAddress,
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
            contextEngineId,
            contextName,
            pduVersion,
            PDU,
            timeout,
            retryCount,
            0,
            getNextHandle(),
            (self.processResponsePdu, (cbFun, cbCtx))            
            )
