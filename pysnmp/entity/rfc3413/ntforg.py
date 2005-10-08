from pysnmp.entity.rfc3413 import config
from pysnmp.proto.api import v2c
from pysnmp.smi import error

vacmID = 3

class NotificationOriginator:
    def __init__(self, snmpContext):
        self.__pendingReqs = {}
        self.__sendRequestHandleSource = 0L
        self.__context = snmpContext
            
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
        # 3.3.6d
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
          sendRequestHandle,
          pendingReqsCount,
          ) = self.__pendingReqs[sendPduHandle]
        del self.__pendingReqs[sendPduHandle]

        pendingReqsCount[0] = pendingReqsCount[0] - 1
        
        if statusInformation: #and statusInformation.has_key('errorIndication')
            if origRetries == origRetryCount:
                if cbFun and not pendingReqsCount[0]:
                    # XXX
                    cbFun(sendRequestHandle, cbCtx)
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

        # 3.3.6c
        if cbFun and not pendingReqsCount[0]:
            # XXX
            cbFun(sendRequestHandle, cbCtx)
        return
        
    def sendNotification(
        self,
        snmpEngine,
        notificationTarget,
        notificationName,
        additionalNames=None,
        contextName='',
        cbFun=None,
        cbCtx=None
        ):
        # 3.3
        ( notifyTag,
          notifyType ) = config.getNotificationInfo(
            snmpEngine, notificationTarget
            )
        pendingReqsCount = { 0: 0 }
        for targetAddrName in config.getTargetNames(snmpEngine, notifyTag):
            ( transportDomain,
              transportAddress,
              timeout,
              retryCount,
              params ) = config.getTargetAddr(snmpEngine, targetAddrName)
            ( messageProcessingModel,
              securityModel,
              securityName,
              securityLevel ) = config.getTargetParams(snmpEngine, params)

            # 3.3.1 XXX
# XXX filtering's yet to be implemented
#             filterProfileName = config.getNotifyFilterProfile(params)

#             ( filterSubtree,
#               filterMask,
#               filterType ) = config.getNotifyFilter(filterProfileName)

            contextMibInstrumCtl = self.__context.getMibInstrum(
                contextName
                )
            
            # 3.3.2
    
            # Get notification objects names
            snmpTrapOid, = apply(
                contextMibInstrumCtl.mibBuilder.importSymbols,
                notificationName
                )
            varNames = []
            for notificationObject in snmpTrapOid.getObjects():
                mibNode = contextMibInstrumCtl.mibBuilder.importSymbol(
                    notificationObject #, mibNode.moduleName # XXX
                    )
                varNames.append(mibNode.name)
    
            if additionalNames:
                varNames.extend(additionalNames)
            
            for varName in varNames:
                try:
                    snmpEngine.accessControlModel[vacmID].isAccessAllowed(
                        snmpEngine, securityModel, securityName,
                        securityLevel, 'notify', contextName, varName
                        )
                except error.SmiError:
                    return

            # 3.3.3
            try:
                snmpEngine.accessControlModel[vacmID].isAccessAllowed(
                    snmpEngine, securityModel, securityName,
                    securityLevel, 'notify', contextName, snmpTrapOid.name
                    )
            except error.SmiError:
                return

            mibTree = contextMibInstrumCtl.mibBuilder.importSymbols(
                'SNMPv2-SMI', 'iso'
                )
            varBinds = []
            for varName in varNames:
                mibNode = mibTree.getNode(varName)
                varBinds.append((varName, mibNode.syntax))
                
            # 3.3.4
            if notifyType == 1:
                pdu = v2c.SNMPv2TrapPDU()
            else:
                pdu = v2c.InformRequestPDU()
            v2c.apiPDU.setDefaults(pdu)
            v2c.apiPDU.setVarBinds(pdu, varBinds)

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                pdu = rfc2576.v2ToV1(pdu)
                pduVersion = 0
            else:
                pduVersion = 1
            
            # 3.3.5
            if notifyType == 1:
                snmpEngine.msgAndPduDsp.sendPdu(
                    snmpEngine,
                    transportDomain,
                    transportAddress,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    self.__context.contextEngineId,
                    contextName,
                    pduVersion,
                    pdu,
                    None
                    )
            else:
                # 3.3.6a
                sendPduHandle = snmpEngine.msgAndPduDsp.sendPdu(
                    snmpEngine,
                    transportDomain,
                    transportAddress,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    self.__context.contextEngineID,
                    contextName,
                    pduVersion,
                    pdu,
                    (self.processResponsePdu, (cbFun, cbCtx))
                    )
                pendingReqsCount[0] = pendingReqsCount[0] + 1                
                # 3.3.6b
                self.__pendingReqs[sendPduHandle] = (
                    transportDomain,
                    transportAddress,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    self.__context.contextEngineID,
                    contextName,
                    pduVersion,
                    pdu,
                    timeout,
                    retryCount,
                    retries + 1,
                    self.__sendRequestHandleSource,
                    pendingReqsCount
                    )

        if cbFun and not pendingReqsCount[0]:
            cbFun(None, None, 0, 0, (), cbCtx)

# XXX
# move/group/implement config setting/retrieval at a stand-alone module

