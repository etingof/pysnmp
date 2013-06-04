import sys
from pyasn1.compat.octets import null
from pysnmp.entity.rfc3413 import config
from pysnmp.proto.proxy import rfc2576
from pysnmp.proto.api import v2c
from pysnmp.proto import error
from pysnmp import nextid
from pysnmp import debug

getNextHandle = nextid.Integer(0x7fffffff)

class NotificationOriginator:
    acmID = 3  # default MIB access control method to use
    def __init__(self, snmpContext):
        self.__pendingReqs = {}
        self.__pendingNotifications = {}
        self.snmpContext = snmpContext

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
        # 3.3.6d
        if sendPduHandle not in self.__pendingReqs:
            raise error.ProtocolError('Missing sendPduHandle %s' % sendPduHandle)

        ( origTransportDomain,
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
          origRetries,
          metaSendPduHandle
          ) = self.__pendingReqs[sendPduHandle]

        del self.__pendingReqs[sendPduHandle]

        self.__pendingNotifications[metaSendPduHandle] -= 1

        snmpEngine.transportDispatcher.jobFinished(id(self))

        if statusInformation:
            debug.logger & debug.flagApp and debug.logger('processResponsePdu: metaSendPduHandle %s, sendPduHandle %s statusInformation %s' % (metaSendPduHandle, sendPduHandle, statusInformation))
            if origRetries == origRetryCount:
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: metaSendPduHandle %s, sendPduHandle %s retry count %d exceeded' % (metaSendPduHandle, sendPduHandle, origRetries))
                if not self.__pendingNotifications[metaSendPduHandle]:
                    del self.__pendingNotifications[metaSendPduHandle]
                    self._handleResponse(
                        metaSendPduHandle,
                        statusInformation['errorIndication'],
                        0, 0, (),
                        cbFun,
                        cbCtx
                    )
                return

            # Convert timeout in seconds into timeout in timer ticks
            timeoutInTicks = float(origTimeout)/100/snmpEngine.transportDispatcher.getTimerResolution()

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                reqPDU = rfc2576.v2ToV1(origPdu)
                pduVersion = 0
            else:
                reqPDU = origPdu
                pduVersion = 1
 
            # 3.3.6a
            try:
                sendPduHandle = snmpEngine.msgAndPduDsp.sendPdu(
                    snmpEngine,
                    origTransportDomain,
                    origTransportAddress,
                    origMessageProcessingModel,
                    origSecurityModel,
                    origSecurityName,
                    origSecurityLevel,
                    origContextEngineId,
                    origContextName,
                    pduVersion,
                    reqPDU,
                    1,                              # expectResponse
                    timeoutInTicks,
                    self.processResponsePdu,
                    (cbFun, cbCtx)
                )
            except error.StatusInformation:
                statusInformation = sys.exc_info()[1]
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: metaSendPduHandle %s: sendPdu() failed with %r ' % (metaSendPduHandle, statusInformation))
                if not self.__pendingNotifications[metaSendPduHandle]:
                    del self.__pendingNotifications[metaSendPduHandle]
                    self._handleResponse(
                        metaSendPduHandle,
                        statusInformation['errorIndication'],
                        0, 0, (),
                        cbFun,
                        cbCtx
                    )
                return

            self.__pendingNotifications[metaSendPduHandle] += 1

            snmpEngine.transportDispatcher.jobStarted(id(self))

            debug.logger & debug.flagApp and debug.logger('processResponsePdu: metaSendPduHandle %s, sendPduHandle %s, timeout %d, retry %d of %d' % (metaSendPduHandle, sendPduHandle, origTimeout, origRetries, origRetryCount))
        
            # 3.3.6b
            self.__pendingReqs[sendPduHandle] = (
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
                metaSendPduHandle
            )
            return

        # 3.3.6c
        if not self.__pendingNotifications[metaSendPduHandle]:
            del self.__pendingNotifications[metaSendPduHandle]

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                PDU = rfc2576.v1ToV2(PDU, origPdu)

            self._handleResponse(metaSendPduHandle, None,
                                 v2c.apiPDU.getErrorStatus(PDU),
                                 v2c.apiPDU.getErrorIndex(PDU,muteErrors=True),
                                 v2c.apiPDU.getVarBinds(PDU),            
                                 cbFun, cbCtx)

    def _handleResponse(self,
                        sendRequestHandle,
                        errorIndication,
                        errorStatus, errorIndex,
                        varBinds,
                        cbFun, cbCtx):
        try:
            # we need to pass response PDU information to user for INFORMs
            cbFun(sendRequestHandle, errorIndication, 
                  errorStatus, errorIndex, varBinds, cbCtx)
        except TypeError:
            # a backward compatible way of calling user function
            cbFun(sendRequestHandle, errorIndication, cbCtx)
    
    def sendNotification(
        self,
        snmpEngine,
        notificationTarget,
        notificationName,
        additionalVarBinds=(),
        cbFun=None,
        cbCtx=None,
        contextName=null,
        instanceIndex=None
        ):
        debug.logger & debug.flagApp and debug.logger('sendNotification: notificationTarget %s, notificationName %s, additionalVarBinds %s, contextName "%s", instanceIndex %s' % (notificationTarget, notificationName, additionalVarBinds, contextName, instanceIndex))

        if contextName:
            __SnmpAdminString, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpAdminString')
            contextName = __SnmpAdminString(contextName)
 
        # 3.3
        ( notifyTag,
          notifyType ) = config.getNotificationInfo(
            snmpEngine, notificationTarget
            )

        metaSendPduHandle = getNextHandle()

        debug.logger & debug.flagApp and debug.logger('sendNotification: metaSendPduHandle %s, notifyTag %s, notifyType %s' % (metaSendPduHandle, notifyTag, notifyType))

        contextMibInstrumCtl = self.snmpContext.getMibInstrum(contextName)
       
        additionalVarBinds = [  (v2c.ObjectIdentifier(x),y) for x,y in additionalVarBinds ]

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

            debug.logger & debug.flagApp and debug.logger('sendNotification: metaSendPduHandle %s, notifyTag %s yields: transportDomain %s, transportAddress %r, securityModel %s, securityName %s, securityLevel %s' % (metaSendPduHandle, notifyTag, transportDomain, transportAddress, securityModel, securityName, securityLevel))

            # 3.3.1 XXX
# XXX filtering's yet to be implemented
#             filterProfileName = config.getNotifyFilterProfile(params)

#             ( filterSubtree,
#               filterMask,
#               filterType ) = config.getNotifyFilter(filterProfileName)

            varBinds = []
            
            # 3.3.2 & 3.3.3
            sysUpTime, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'sysUpTime')

            for varName, varVal in additionalVarBinds:
                if varName == sysUpTime.name:
                    varBinds.append((varName, varVal))
                    break
            if not varBinds:
                varBinds.append((sysUpTime.name,
                                 sysUpTime.syntax.clone())) # for actual value

            snmpTrapOid, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpTrapOID')
            if len(notificationName) == 2:  # ('MIB', 'symbol')
                notificationTypeObject, = contextMibInstrumCtl.mibBuilder.importSymbols(*notificationName)
                varBinds.append((snmpTrapOid.name, v2c.ObjectIdentifier(notificationTypeObject.name)))
                debug.logger & debug.flagApp and debug.logger('sendNotification: notification type object is %s' % notificationTypeObject)
                for notificationObject in notificationTypeObject.getObjects():
                    mibNode, = contextMibInstrumCtl.mibBuilder.importSymbols(*notificationObject)
                    if instanceIndex:
                        mibNode = mibNode.getNode(mibNode.name + instanceIndex)
                    else:
                        mibNode = mibNode.getNextNode(mibNode.name)
                    varBinds.append((mibNode.name, mibNode.syntax))
                    debug.logger & debug.flagApp and debug.logger('sendNotification: processed notification object %s, instance index %s, var-bind %s' % (notificationObject, instanceIndex is None and "<first>" or instanceIndex, mibNode))
            elif notificationName:  # numeric OID
                varBinds.append(
                    (snmpTrapOid.name,
                     snmpTrapOid.syntax.clone(notificationName))
                )
            else:
                varBinds.append((snmpTrapOid.name, snmpTrapOid.syntax))

            for varName, varVal in additionalVarBinds:
                if varName in (sysUpTime.name, snmpTrapOid.name):
                    continue
                try:
                    snmpEngine.accessControlModel[self.acmID].isAccessAllowed(
                        snmpEngine, securityModel, securityName,
                        securityLevel, 'notify', contextName, varName
                        )
                except error.StatusInformation:
                    debug.logger & debug.flagApp and debug.logger('sendNotification: OID %s not allowed for %s, droppping notification' % (varName, securityName))
                    return
                else:
                    varBinds.append((varName, varVal))

            # 3.3.4
            if notifyType == 1:
                pdu = v2c.SNMPv2TrapPDU()
            elif notifyType == 2:
                pdu = v2c.InformRequestPDU()
            else:
                raise RuntimeError()
            v2c.apiPDU.setDefaults(pdu)
            v2c.apiPDU.setVarBinds(pdu, varBinds)

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                reqPDU = rfc2576.v2ToV1(pdu)
                pduVersion = 0
            else:
                reqPDU = pdu
                pduVersion = 1
            
            # 3.3.5
            if notifyType == 1:
                try:
                    snmpEngine.msgAndPduDsp.sendPdu(
                        snmpEngine,
                        transportDomain,
                        transportAddress,
                        messageProcessingModel,
                        securityModel,
                        securityName,
                        securityLevel,
                        self.snmpContext.contextEngineId,
                        contextName,
                        pduVersion,
                        reqPDU,
                        None
                    )
                except error.StatusInformation:
                    statusInformation = sys.exc_info()[1]
                    debug.logger & debug.flagApp and debug.logger('sendReq: metaSendPduHandle %s: sendPdu() failed with %r' % (metaSendPduHandle, statusInformation))
                    if not self.__pendingNotifications[metaSendPduHandle]:
                        del self.__pendingNotifications[metaSendPduHandle]
                        self._handleResponse(
                            metaSendPduHandle,
                            statusInformation['errorIndication'],
                            0, 0, (),
                            cbFun,
                            cbCtx
                        )
                    return metaSendPduHandle
            else:
                # Convert timeout in seconds into timeout in timer ticks
                timeoutInTicks = float(timeout)/100/snmpEngine.transportDispatcher.getTimerResolution()

                # 3.3.6a
                try:
                    sendPduHandle = snmpEngine.msgAndPduDsp.sendPdu(
                        snmpEngine,
                        transportDomain,
                        transportAddress,
                        messageProcessingModel,
                        securityModel,
                        securityName,
                        securityLevel,
                        self.snmpContext.contextEngineId,
                        contextName,
                        pduVersion,
                        reqPDU,
                        1,                      # expectResponse
                        timeoutInTicks,
                        self.processResponsePdu,
                        (cbFun, cbCtx)
                    )
                except error.StatusInformation:
                    statusInformation = sys.exc_info()[1]
                    debug.logger & debug.flagApp and debug.logger('sendReq: metaSendPduHandle %s: sendPdu() failed with %r' % (metaSendPduHandle, statusInformation))
                    if not self.__pendingNotifications[metaSendPduHandle]:
                        del self.__pendingNotifications[metaSendPduHandle]
                        self._handleResponse(
                            metaSendPduHandle,
                            statusInformation['errorIndication'],
                            0, 0, (),
                            cbFun,
                            cbCtx
                        )
                    return metaSendPduHandle

                debug.logger & debug.flagApp and debug.logger('sendNotification: metaSendPduHandle %s, sendPduHandle %s, timeout %d' % (metaSendPduHandle, sendPduHandle, timeout))
                
                # 3.3.6b
                self.__pendingReqs[sendPduHandle] = (
                    transportDomain,
                    transportAddress,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    self.snmpContext.contextEngineId,
                    contextName,
                    pdu,
                    timeout,
                    retryCount,
                    1,
                    metaSendPduHandle
                )
               
                if metaSendPduHandle not in self.__pendingNotifications:
                    self.__pendingNotifications[metaSendPduHandle] = 0
                self.__pendingNotifications[metaSendPduHandle] += 1

                snmpEngine.transportDispatcher.jobStarted(id(self))

        debug.logger & debug.flagApp and debug.logger('sendNotification: metaSendPduHandle %s, notification(s) sent' % metaSendPduHandle)

        return metaSendPduHandle

# XXX
# move/group/implement config setting/retrieval at a stand-alone module

