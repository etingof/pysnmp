from pysnmp.entity import config
from pysnmp.entity.rfc3413 import config, context

vacmID = 3

class NotificationOriginator:
    def __init__(self, snmpContext=None):
        self.__pendingReqs = {}
        self.__sendRequestHandleSource = 0L
        if snmpContext is None:
            self.snmpContext = context.SnmpContext
        else:
            self.snmpContext = snmpContext
            
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
              params ) = config.getTargetAddr(snmpEngine, notifyTag)
            ( messageProcessingModel,
              securityModel,
              securityName,
              securityLevel ) = config.getTargetParams(snmpEngine, params)
        
            filterProfileName = config.getNotifyFilterProfile(params)

            ( filterSubtree,
              filterMask,
              filterType ) = config.getNotifyFilter(filterProfileName)

            contextMibInstrumCtl = self.snmpContext.getMibInstrum(
                contextName
                )
            
            # 3.3.1 XXX
    
            # 3.3.2
    
            # Get notification objects names
            mibTree, = contextMibInstrumCtl.mibBuilder.importSymbols(
                'SNMPv2-SMI', 'iso'
                )
            varNames = []
            mibNode = mibTree.getNode(tuple(notificationName))
            for notificationObject in mibNode.getObjects():
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
                except pysnmp.smi.error.SmiError:
                    return
    
            # 3.3.3
            try:
                snmpEngine.accessControlModel[vacmID].isAccessAllowed(
                    snmpEngine, securityModel, securityName,
                    securityLevel, 'notify', contextName, mibNode.name
                    )
            except pysnmp.smi.error.SmiError:
                return
    
            # 3.3.4
            if snmpNotifyType == 1:            
                pdu = v2c.SNMPv2TrapPDU()
            else:
                pdu = v2c.InformRequestPDU()
            pMod.apiPDU.setDefaults(reqPDU)            
            v1c.apiTrapPDU.setVarBinds(pdu, varBinds)
            
            # 3.3.5
            if snmpNotifyType == 1:
                snmpEngine.msgAndPduDsp.sendPdu(
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
            cbFun(None, cbCtx)

# XXX
# move/group/implement config setting/retrieval at a stand-alone module

