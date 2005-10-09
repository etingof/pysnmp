from pysnmp.entity.rfc3413 import config
from pysnmp.proto.proxy import rfc2576
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
        cbCtx
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
          origSendRequestHandle
          ) = self.__pendingReqs[sendPduHandle]
        del self.__pendingReqs[sendPduHandle]

        snmpEngine.transportDispatcher.jobFinished(id(self))
        
        if statusInformation and origRetries != origRetryCount:
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
                (self.processResponsePdu, cbCtx)
                )
            return

        # 3.3.6c
        pass
    
    def sendNotification(
        self,
        snmpEngine,
        notificationTarget,
        notificationName,
        additionalVarBinds=None,
        contextName='',
        cbCtx=None
        ):
        # 3.3
        ( notifyTag,
          notifyType ) = config.getNotificationInfo(
            snmpEngine, notificationTarget
            )
        contextMibInstrumCtl = self.__context.getMibInstrum(
            contextName
            )
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

            varBinds = []
            
            # 3.3.2 & 3.3.3
            sysUpTime, = contextMibInstrumCtl.mibBuilder.importSymbols(
                'SNMPv2-MIB', 'sysUpTime'
                )
            varBinds.append((sysUpTime.name, sysUpTime.syntax))

            snmpTrapOid, = apply(
                contextMibInstrumCtl.mibBuilder.importSymbols,
                notificationName
                )
            varBinds.append((snmpTrapOid.name, v2c.Null()))
            
            # Get notification objects names
            for notificationObject in snmpTrapOid.getObjects():
                mibNode, = contextMibInstrumCtl.mibBuilder.importSymbols(
                    notificationObject #, mibNode.moduleName # XXX
                    )
                varBinds.append((mibNode.name, mibNode.syntax))

            if additionalVarBinds:
                varBinds.extend(additionalVarBinds)

            for varName, varVal in varBinds:
                try:
                    snmpEngine.accessControlModel[vacmID].isAccessAllowed(
                        snmpEngine, securityModel, securityName,
                        securityLevel, 'notify', contextName, varName
                        )
                except error.SmiError:
                    return

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
                    self.__sendRequestHandleSource
                    )
                
                snmpEngine.transportDispatcher.jobStarted(id(self))

# XXX
# move/group/implement config setting/retrieval at a stand-alone module

