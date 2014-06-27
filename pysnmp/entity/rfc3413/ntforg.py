import sys
from pyasn1.compat.octets import null
from pysnmp.entity.rfc3413 import config
from pysnmp.proto.proxy import rfc2576
from pysnmp.proto import rfc3411
from pysnmp.proto.api import v2c
from pysnmp.proto import error
from pysnmp import nextid
from pysnmp import debug

getNextHandle = nextid.Integer(0x7fffffff)

class NotificationOriginator:
    acmID = 3  # default MIB access control method to use
    def __init__(self, snmpContext=None):
        self.__pendingReqs = {}
        self.__sendRequestHandles = {}
        self.__pendingNotifications = {}
        self.snmpContext = snmpContext  # this is deprecated

    def processResponsePdu(self,
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
                           cbInfo):
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
          origRetries ) = self.__pendingReqs.pop(sendPduHandle)

        sendRequestHandle = self.__sendRequestHandles.pop(sendPduHandle)

        self.__pendingNotifications[sendRequestHandle] -= 1

        snmpEngine.transportDispatcher.jobFinished(id(self))

        if statusInformation:
            debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendRequestHandle %s, sendPduHandle %s statusInformation %s' % (sendRequestHandle, sendPduHandle, statusInformation))
            if origRetries == origRetryCount:
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendRequestHandle %s, sendPduHandle %s retry count %d exceeded' % (sendRequestHandle, sendPduHandle, origRetries))
                if not self.__pendingNotifications[sendRequestHandle]:
                    del self.__pendingNotifications[sendRequestHandle]
                    cbFun(snmpEngine,
                          sendRequestHandle,
                          statusInformation['errorIndication'],
                          None,
                          cbCtx)
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
                debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendRequestHandle %s: sendPdu() failed with %r ' % (sendRequestHandle, statusInformation))
                if not self.__pendingNotifications[sendRequestHandle]:
                    del self.__pendingNotifications[sendRequestHandle]
                    cbFun(snmpEngine,
                          sendRequestHandle,
                          statusInformation['errorIndication'],
                          None,
                          cbCtx)
                return

            self.__pendingNotifications[sendRequestHandle] += 1

            snmpEngine.transportDispatcher.jobStarted(id(self))

            debug.logger & debug.flagApp and debug.logger('processResponsePdu: sendRequestHandle %s, sendPduHandle %s, timeout %d, retry %d of %d' % (sendRequestHandle, sendPduHandle, origTimeout, origRetries, origRetryCount))
        
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
                origRetries + 1
            )
            self.__sendRequestHandles[sendPduHandle] = sendRequestHandle
            
            return

        # 3.3.6c
        if not self.__pendingNotifications[sendRequestHandle]:
            del self.__pendingNotifications[sendRequestHandle]

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                PDU = rfc2576.v1ToV2(PDU, origPdu)

            cbFun(snmpEngine, sendRequestHandle, None, PDU, cbCtx)

    def sendPdu(self,
                snmpEngine,
                targetName,
                contextEngineId,
                contextName,
                pdu,
                cbFun=None,
                cbCtx=None):
        ( transportDomain,
          transportAddress,
          timeout,
          retryCount,
          params ) = config.getTargetAddr(snmpEngine, targetName)
          
        ( messageProcessingModel,
          securityModel,
          securityName,
          securityLevel ) = config.getTargetParams(snmpEngine, params)

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            reqPDU = rfc2576.v2ToV1(pdu)
            pduVersion = 0
        else:
            reqPDU = pdu
            pduVersion = 1

        # 3.3.5
        if reqPDU.tagSet in rfc3411.confirmedClassPDUs:
            # Convert timeout in seconds into timeout in timer ticks
            timeoutInTicks = float(timeout)/100/snmpEngine.transportDispatcher.getTimerResolution()

            cbCtx = cbFun, cbCtx
            cbFun = self.processResponsePdu
            
            # 3.3.6a
            sendPduHandle = snmpEngine.msgAndPduDsp.sendPdu(snmpEngine,
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
                                                            # expectResponse
                                                            1,
                                                            timeoutInTicks,
                                                            cbFun,
                                                            cbCtx)

            debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendPduHandle %s, timeout %d' % (sendPduHandle, timeout))

            # 3.3.6b
            self.__pendingReqs[sendPduHandle] = (
                transportDomain,
                transportAddress,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pdu,
                timeout,
                retryCount,
                1
            )
            snmpEngine.transportDispatcher.jobStarted(id(self))            
        else:
            snmpEngine.msgAndPduDsp.sendPdu(snmpEngine,
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
                                            None)  # do not expectResponse

            sendPduHandle = None

            debug.logger & debug.flagApp and debug.logger('sendVarBinds: message sent')

        return sendPduHandle

    def processResponseVarBinds(self,
                                snmpEngine,
                                sendRequestHandle,
                                errorIndication,
                                pdu,
                                cbCtx):
        cbFun, cbCtx = cbCtx
        cbFun(snmpEngine,
              sendRequestHandle,
              errorIndication,
              pdu and v2c.apiPDU.getErrorStatus(pdu) or 0,
              pdu and v2c.apiPDU.getErrorIndex(pdu, muteErrors=True) or 0,
              pdu and v2c.apiPDU.getVarBinds(pdu) or (),
              cbCtx)
    
    def sendVarBinds(self,
                     snmpEngine,
                     notificationTarget,
                     snmpContext,
                     contextName,
                     notificationName,
                     instanceIndex,
                     additionalVarBinds=(),
                     cbFun=None,
                     cbCtx=None):
        debug.logger & debug.flagApp and debug.logger('sendVarBinds: notificationTarget %s, notificationName %s, additionalVarBinds %s, contextName "%s", instanceIndex %s' % (notificationTarget, notificationName, additionalVarBinds, contextName, instanceIndex))

        if contextName:
            __SnmpAdminString, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpAdminString')
            contextName = __SnmpAdminString(contextName)
 
        # 3.3
        ( notifyTag,
          notifyType ) = config.getNotificationInfo(
                snmpEngine, notificationTarget
            )

        sendRequestHandle = getNextHandle()

        debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendRequestHandle %s, notifyTag %s, notifyType %s' % (sendRequestHandle, notifyTag, notifyType))

        contextMibInstrumCtl = snmpContext.getMibInstrum(contextName)
       
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

            debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendRequestHandle %s, notifyTag %s yields: transportDomain %s, transportAddress %r, securityModel %s, securityName %s, securityLevel %s' % (sendRequestHandle, notifyTag, transportDomain, transportAddress, securityModel, securityName, securityLevel))

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
                debug.logger & debug.flagApp and debug.logger('sendVarBinds: notification type object is %s' % notificationTypeObject)
                for notificationObject in notificationTypeObject.getObjects():
                    mibNode, = contextMibInstrumCtl.mibBuilder.importSymbols(*notificationObject)
                    if instanceIndex:
                        mibNode = mibNode.getNode(mibNode.name + instanceIndex)
                    else:
                        mibNode = mibNode.getNextNode(mibNode.name)
                    varBinds.extend(
                        contextMibInstrumCtl.readVars(
                            [ (mibNode.name, None) ]  # XXX AC is missing
                        )
                    )
                    debug.logger & debug.flagApp and debug.logger('sendVarBinds: processed notification object %s, instance index %s, var-bind %s' % (notificationObject, instanceIndex is None and "<first>" or instanceIndex, mibNode))
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
                    debug.logger & debug.flagApp and debug.logger('sendVarBinds: OID %s not allowed for %s, droppping notification' % (varName, securityName))
                    return
                else:
                    varBinds.append((varName, varVal))

            # 3.3.4
            if notifyType == 1:
                pdu = v2c.SNMPv2TrapPDU()
            elif notifyType == 2:
                pdu = v2c.InformRequestPDU()
            else:
                raise error.ProtocolError('Unknown notify-type %r', notifyType)
            
            v2c.apiPDU.setDefaults(pdu)
            v2c.apiPDU.setVarBinds(pdu, varBinds)

            cbCtx = cbFun, cbCtx
            cbFun = self.processResponseVarBinds
            
            # 3.3.5
            try:
                sendPduHandle = self.sendPdu(snmpEngine,
                                             targetAddrName,
                                             snmpContext.contextEngineId,
                                             contextName,
                                             pdu,
                                             cbFun,
                                             cbCtx)
                
            except error.StatusInformation:
                statusInformation = sys.exc_info()[1]
                debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendRequestHandle %s: sendVarBindsPdu() failed with %r' % (sendRequestHandle, statusInformation))
                if sendRequestHandle not in self.__pendingNotifications or \
                       not self.__pendingNotifications[sendRequestHandle]:
                    if sendRequestHandle in self.__pendingNotifications:
                        del self.__pendingNotifications[sendRequestHandle]
                    cbFun(snmpEngine,
                          sendRequestHandle,
                          statusInformation['errorIndication'],
                          None,
                          cbCtx)
                return sendRequestHandle

            debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendRequestHandle %s, timeout %d' % (sendRequestHandle, timeout))

            if notifyType == 2:
                if sendRequestHandle not in self.__pendingNotifications:
                    self.__pendingNotifications[sendRequestHandle] = 0
                self.__pendingNotifications[sendRequestHandle] += 1
                self.__sendRequestHandles[sendPduHandle] = sendRequestHandle

        debug.logger & debug.flagApp and debug.logger('sendVarBinds: sendRequestHandle %s, notification(s) sent' % sendRequestHandle)

        return sendRequestHandle

#
# Obsolete, compatibility interfaces.
#

def _sendNotificationCbFun(snmpEngine,
                           sendRequestHandle,
                           errorIndication,
                           errorStatus,
                           errorIndex,
                           varBinds,
                           cbCtx):
    cbFun, cbCtx = cbCtx
        
    try:
        # we need to pass response PDU information to user for INFORMs
        cbFun(sendRequestHandle, errorIndication, 
              errorStatus, errorIndex, varBinds, cbCtx)
    except TypeError:
        # a backward compatible way of calling user function
        cbFun(sendRequestHandle, errorIndication, cbCtx)

def _sendNotification(self,
                      snmpEngine,
                      notificationTarget,
                      notificationName,
                      additionalVarBinds=(),
                      cbFun=None,
                      cbCtx=None,
                      contextName=null,
                      instanceIndex=None):
    if self.snmpContext is None:
        raise error.ProtocolError('SNMP context not specified')
        
    cbCtx = cbFun, cbCtx
    cbFun = _sendNotificationCbFun

    return self.sendVarBinds(snmpEngine,
                             notificationTarget,
                             self.snmpContext,
                             contextName,
                             notificationName,
                             instanceIndex,
                             additionalVarBinds,
                             cbFun,
                             cbCtx)

# install compatibility wrapper
NotificationOriginator.sendNotification = _sendNotification
    
# XXX
# move/group/implement config setting/retrieval at a stand-alone module

