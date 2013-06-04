import sys
from pysnmp.entity.rfc3413 import config
from pysnmp.proto import rfc1905, errind
from pysnmp.proto.api import v2c
from pysnmp.proto.proxy import rfc2576
from pysnmp import error, nextid, debug
from pysnmp.proto.error import StatusInformation
from pyasn1.type import univ

getNextHandle = nextid.Integer(0x7fffffff)
                             
__null = univ.Null('')
    
def getNextVarBinds(origVarBinds, varBinds):
    errorIndication = None
    idx = nonNulls = len(varBinds)
    rspVarBinds = []
    while idx:
        idx = idx - 1
        if varBinds[idx][1].tagSet in (rfc1905.NoSuchObject.tagSet,
                                       rfc1905.NoSuchInstance.tagSet,
                                       rfc1905.EndOfMibView.tagSet):
            nonNulls = nonNulls - 1
        elif origVarBinds[idx][0].asTuple() >= varBinds[idx][0].asTuple():
            errorIndication = errind.oidNotIncreasing
            
        rspVarBinds.insert(0, (varBinds[idx][0], __null))

    if not nonNulls:
        rspVarBinds = []
        
    return errorIndication, rspVarBinds

class CommandGeneratorBase:
    _null = univ.Null('')
    def __init__(self):
        self.__pendingReqs = {}
        self.__SnmpEngineID, self.__SnmpAdminString = None, None
            
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
        cbInfo
        ):
        (cbFun, cbCtx) = cbInfo
        # 3.1.1
        if sendPduHandle not in self.__pendingReqs:
            raise error.PySnmpError('Missing sendPduHandle %s' % sendPduHandle)

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
          origSendRequestHandle ) = self.__pendingReqs[sendPduHandle]
  
        del self.__pendingReqs[sendPduHandle]

        snmpEngine.transportDispatcher.jobFinished(id(self))

        # 3.1.3
        if statusInformation:
            debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendPduHandle %s, statusInformation %s' % (sendPduHandle, statusInformation))
            errorIndication = statusInformation['errorIndication']
            # SNMP engine discovery will take extra retries, allow that
            if errorIndication in (errind.notInTimeWindow,
                                   errind.unknownEngineID) and \
                                   origRetries == origRetryCount + 2 or \
               errorIndication not in (errind.notInTimeWindow,
                                       errind.unknownEngineID) and \
                                   origRetries == origRetryCount:
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendPduHandle %s, retry count %d exceeded' % (sendPduHandle, origRetries))
                cbFun(origSendRequestHandle,
                      statusInformation['errorIndication'], 0, 0, (),
                      cbCtx)
                return
            try:
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
                    origPdu,
                    origTimeout,
                    origRetryCount,
                    origRetries + 1,
                    origSendRequestHandle,
                    (self.processResponsePdu, (cbFun, cbCtx))
                )
            except StatusInformation:
                statusInformation = sys.exc_info()[1]
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: origSendRequestHandle %s, _sendPdu() failed with %r' % (sendPduHandle, statusInformation))
                cbFun(origSendRequestHandle,
                      statusInformation['errorIndication'], 0, 0, (),
                      cbCtx)
            return

        if origMessageProcessingModel != messageProcessingModel or \
           origSecurityModel != securityModel or \
           origSecurityName != origSecurityName or \
           origContextEngineId and origContextEngineId != contextEngineId or \
           origContextName and origContextName != contextName or \
           origPduVersion != pduVersion:
            debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendPduHandle %s, request/response data mismatch' % sendPduHandle)
            cbFun(origSendRequestHandle, 'badResponse', 0, 0, (), cbCtx)
            return

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1ToV2(PDU, origPdu)
 
        # 3.1.2
        if v2c.apiPDU.getRequestID(PDU) != v2c.apiPDU.getRequestID(origPdu):
            debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendPduHandle %s, request-id/response-id mismatch' % sendPduHandle)
            cbFun(origSendRequestHandle, 'badResponse', 0, 0, (), cbCtx)
            return

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
            origPdu,
            origTimeout,
            origRetryCount,
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
        raise error.PySnmpError('Method not implemented')

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
        reqPDU,
        timeout,
        retryCount,
        retries,
        sendRequestHandle,
        cbInfo
        ):
        (processResponsePdu, cbCtx) = cbInfo

        # Convert timeout in seconds into timeout in timer ticks
        timeoutInTicks = float(timeout)/100/snmpEngine.transportDispatcher.getTimerResolution()

        if not self.__SnmpEngineID or not self.__SnmpAdminString:
            self.__SnmpEngineID, self.__SnmpAdminString = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpEngineID', 'SnmpAdminString')

        # Cast possible strings into bytes
        if contextEngineId:
            contextEngineId = self.__SnmpEngineID(contextEngineId)
        contextName = self.__SnmpAdminString(contextName)

        origPDU = reqPDU

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            reqPDU = rfc2576.v2ToV1(reqPDU)
            pduVersion = 0
        else:
            pduVersion = 1
 
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
            1, # expectResponse
            timeoutInTicks,
            processResponsePdu,
            cbCtx
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
            origPDU,
            timeout,
            retryCount,
            retries,
            sendRequestHandle
        )
 
        debug.logger & debug.flagApp and debug.logger('_sendPdu: sendPduHandle %s, timeout %d*10 ms/%d ticks, retry %d of %d' % (sendPduHandle, timeout, timeoutInTicks, retries, retryCount))

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
        PDU,
        timeout,
        retryCount,
        rspPDU,
        sendRequestHandle,
        cbInfo
        ):
        (cbFun, cbCtx) = cbInfo        
        cbFun(sendRequestHandle,
              None,
              v2c.apiPDU.getErrorStatus(rspPDU),
              v2c.apiPDU.getErrorIndex(rspPDU, muteErrors=True),
              v2c.apiPDU.getVarBinds(rspPDU),
              cbCtx)

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

        reqPDU = v2c.GetRequestPDU()
        v2c.apiPDU.setDefaults(reqPDU)
        
        v2c.apiPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()

        try:        
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
                reqPDU,
                timeout,
                retryCount,
                0, # retries
                requestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (requestHandle, statusInformation))
            cbFun(requestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)

        return requestHandle
    
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

        reqPDU = v2c.SetRequestPDU()
        v2c.apiPDU.setDefaults(reqPDU)

        v2c.apiPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()        

        try:        
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
                reqPDU,
                timeout,
                retryCount,
                0, # retries
                requestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (requestHandle, statusInformation))
            cbFun(requestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)

        return requestHandle

class NextCommandGeneratorSingleRun(CommandGeneratorBase):
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

        reqPDU = v2c.GetNextRequestPDU()
        v2c.apiPDU.setDefaults(reqPDU)
        
        v2c.apiPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()        

        try:        
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
                reqPDU,
                timeout,
                retryCount,
                0, # retries
                requestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (requestHandle, statusInformation))
            cbFun(requestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)

        return requestHandle
 
class NextCommandGenerator(NextCommandGeneratorSingleRun):
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
        PDU,
        timeout,
        retryCount,
        rspPDU,
        sendRequestHandle,
        cbInfo
        ):
        (cbFun, cbCtx) = cbInfo

        varBindTable = v2c.apiPDU.getVarBindTable(PDU, rspPDU)

        if v2c.apiPDU.getErrorStatus(rspPDU):
            errorIndication, varBinds = None, ()
        elif not varBindTable:
            errorIndication, varBinds = errind.emptyResponse, ()
        else:
            errorIndication, varBinds = getNextVarBinds(
                v2c.apiPDU.getVarBinds(PDU), varBindTable[-1]
            )
        
        if not cbFun(sendRequestHandle, errorIndication,
                     v2c.apiPDU.getErrorStatus(rspPDU),
                     v2c.apiPDU.getErrorIndex(rspPDU, muteErrors=True),
                     varBindTable, cbCtx):
            debug.logger & debug.flagApp and debug.logger('_handleResponse: sendRequestHandle %s, app says to stop walking' % sendRequestHandle)
            return  # app says enough

        if not varBinds:
            return # no more objects available
    
        v2c.apiPDU.setRequestID(PDU, v2c.getNextRequestID())
        v2c.apiPDU.setVarBinds(PDU, varBinds)

        sendRequestHandle = getNextHandle()

        try:
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
                PDU,
                timeout,
                retryCount,
                0, # retries
                sendRequestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (sendRequestHandle, statusInformation))
            cbFun(sendRequestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)
 
class BulkCommandGeneratorSingleRun(CommandGeneratorBase):
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

        reqPDU = v2c.GetBulkRequestPDU()
        v2c.apiBulkPDU.setDefaults(reqPDU)
        
        v2c.apiBulkPDU.setNonRepeaters(reqPDU, nonRepeaters)
        v2c.apiBulkPDU.setMaxRepetitions(reqPDU, maxRepetitions)

        v2c.apiBulkPDU.setVarBinds(reqPDU, varBinds)

        requestHandle = getNextHandle()        

        try:        
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
                reqPDU,
                timeout,
                retryCount,
                0, # retries
                requestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (requestHandle, statusInformation))
            cbFun(requestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)

        return requestHandle
 
class BulkCommandGenerator(BulkCommandGeneratorSingleRun):
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
        PDU,
        timeout,
        retryCount,
        rspPDU,
        sendRequestHandle,
        cbInfo
        ):
        (cbFun, cbCtx) = cbInfo        
        varBindTable = v2c.apiBulkPDU.getVarBindTable(PDU, rspPDU)

        if v2c.apiBulkPDU.getErrorStatus(rspPDU):
            errorIndication, varBinds = None, ()
        elif not varBindTable:
            errorIndication, varBinds = errind.emptyResponse, ()
        else:
            errorIndication, varBinds = getNextVarBinds(
                v2c.apiBulkPDU.getVarBinds(PDU), varBindTable[-1]
            )

        if not cbFun(sendRequestHandle, errorIndication,
                     v2c.apiBulkPDU.getErrorStatus(rspPDU),
                     v2c.apiBulkPDU.getErrorIndex(rspPDU, muteErrors=True),
                     varBindTable, cbCtx):
            debug.logger & debug.flagApp and debug.logger('_handleResponse: sendRequestHandle %s, app says to stop walking' % sendRequestHandle)
            return # app says enough

        if not varBinds:
            return # no more objects available
    
        v2c.apiBulkPDU.setRequestID(PDU, v2c.getNextRequestID())
        v2c.apiBulkPDU.setVarBinds(PDU, varBinds)

        sendRequestHandle = getNextHandle()

        try:        
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
                PDU,
                timeout,
                retryCount,
                0, # retries
                sendRequestHandle,
                (self.processResponsePdu, (cbFun, cbCtx))            
            )
        except StatusInformation:
            statusInformation = sys.exc_info()[1]
            debug.logger & debug.flagApp and debug.logger('sendReq: sendPduHandle %s: _sendPdu() failed with %r' % (sendRequestHandle, statusInformation))
            cbFun(sendRequestHandle, statusInformation['errorIndication'],
                  0, 0, (), cbCtx)
