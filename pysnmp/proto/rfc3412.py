"""SNMP v3 Message Processing and Dispatching (RFC3412)"""
from pysnmp.smi import builder, instrum
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import error
from pysnmp.proto.msgproc import rfc2576, demux
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pysnmp.error import PySnmpError

__all__ = [ 'MsgAndPduDispatcher' ]

# Defaults
defaultMessageProcessingVersion = rfc2576.snmpV1MessageProcessingModelId

class AbstractApplication:
    # Dispatcher registration protocol
    contextEngineId = None
    # ((pduVersion, pduType), ...)
    pduTypes = (())        

    def processPdu(self, dsp, **kwargs):
        raise error.BadArgumentError(
            'App %s doesn\'t accept request PDUs' % (self)
            )
    def processResponsePdu(self, dsp, **kwargs):
        raise error.BadArgumentError(
            'App %s doesn\'t accept response PDUs' % (self)
            )

class MsgAndPduDispatcher:
    """SNMP engine PDU & message dispatcher. Exchanges SNMP PDU's with
       applications and serialized messages with transport level.
    """
    def __init__(self, transportDispatcher=None, mibInstrumController=None):
        self.transportDispatcher = None

        if transportDispatcher is None:
            # XXX load all available transports by default
            # Default is Manager (client) mode over UDP
            self.registerTransportDispatcher(
                AsynsockDispatcher(udp=UdpSocketTransport())
                )
        else:
            self.registerTransportDispatcher(transportDispatcher)

        if mibInstrumController is None:
            self.mibInstrumController = instrum.MibInstrumController(
                builder.MibBuilder()
                )
        else:
            self.mibInstrumController = mibInstrumController
            
        self.mibInstrumController.mibBuilder.loadModules(
            'SNMP-MPD-MIB', 'SNMP-COMMUNITY-MIB', 'SNMP-TARGET-MIB',
            'SNMP-USER-BASED-SM-MIB'
            )
                          
        # Versions to subsystems mapping
        self.messageProcessingSubsystems = {
            rfc2576.snmpV1MessageProcessingModelId:
            rfc2576.SnmpV1MessageProcessingModel(self.mibInstrumController),
            rfc2576.snmpV2cMessageProcessingModelId:
            rfc2576.SnmpV2cMessageProcessingModel(self.mibInstrumController),
            }

        self.__msgDemuxer = demux.SnmpMsgDemuxer()
        
        # Registered context engine IDs
        self.__appsRegistration = {}

        # Source of sendPduHandle and cache of requesting apps
        self.__sendPduHandle = 0L
        self.__cacheRepository = {}

    # Register/unregister with transport dispatcher
    def registerTransportDispatcher(self, transportDispatcher):
        if self.transportDispatcher is not None:
            raise error.BadArgumentError(
                'Transport dispatcher already registered'
                )
        transportDispatcher.registerRecvCbFun(
            self.receiveMessage
            )
        transportDispatcher.registerTimerCbFun(
            self.__receiveTimerTick
            )        
        self.transportDispatcher = transportDispatcher

    def unregisterTransportDispatcher(self):
        if self.transportDispatcher is None:
            raise error.BadArgumentError(
                'Transport dispatcher not registered'
                )
        self.transportDispatcher.unregisterRecvCbFun()
        self.transportDispatcher.unregisterTimerCbFun()
        self.transportDispatcher = None

    # These routines manage cache of management apps

    def __newSendPduHandle(self):
        sendPduHandle = self.__sendPduHandle = self.__sendPduHandle + 1
        return sendPduHandle
    
    def __cacheAdd(self, index, **kwargs):
        self.__cacheRepository[index] = kwargs
        return index

    def __cachePop(self, index):
        cachedParams = self.__cacheRepository.get(index)
        if cachedParams is None:
            return
        del self.__cacheRepository[index]
        return cachedParams

    def __cacheUpdate(self, index, **kwargs):
        if not self.__cacheRepository.has_key(index):
            raise error.BadArgumentError(
                'Cache miss on update for %s' % kwargs
                )
        self.__cacheRepository[index].update(kwargs)
            
    def __cacheExpire(self, cbFun):
        for index, cachedParams in self.__cacheRepository.items():
            if cbFun:
                if cbFun(cachedParams):
                    del self.__cacheRepository[index]                    

    # Application registration with dispatcher

    # 4.3.1
    def registerContextEngineId(self, app):
        """Register application with dispatcher"""
        # 4.3.2 -> noop
        contextEngineId = app.contextEngineId
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId,= self.mibInstrumController.mibBuilder.importSymbols(
                'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
                )
            contextEngineId = contextEngineId.syntax.get()

        # 4.3.3
        for pduVersion, pduType in app.pduTypes:
            k = (contextEngineId, pduVersion, pduType)
            if self.__appsRegistration.has_key(k):
                raise error.BadArgumentError(
                    'Duplicate registration %s/%s/%s' %
                    (contextEngineId, pduVersion, pduType)
                    )

            # 4.3.4
            self.__appsRegistration[k] = app
        
    # 4.4.1
    def unregisterContextEngineId(self, app):
        """Unregister application with dispatcher"""
        # 4.3.4
        contextEngineId = app.contextEngineId
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId, = self.mibInstrumController.mibBuilder.importSymbols(
                'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
                ).syntax.get()

        for pduVersion, pduType in app.pduTypes:
            k = (contextEngineId, pduVersion, pduType)
            if self.__appsRegistration.has_key(k):
                del self.__appsRegistration[k]

    def getRegisteredApp(self, contextEngineId, pduVersion, pduType):
        return self.__appsRegistration.get(
            (contextEngineId, pduVersion, pduType)
            )

    # Dispatcher <-> application API
    
    # 4.1.1
    
    def sendPdu(self, **kwargs):
        """PDU dispatcher -- prepare and serialize a request or notification"""
        # 4.1.1.2
        messageProcessingModel = kwargs.get(
            'messageProcessingModel', defaultMessageProcessingVersion
            )
        mpHandler = self.messageProcessingSubsystems.get(messageProcessingModel)
        if mpHandler is None:
            raise error.BadArgumentError(
                'Unknown messageProcessingModel: %s' % messageProcessingModel
                )
        mpInParams = {}
        mpInParams.update(kwargs)
        
        # 4.1.1.3
        mpInParams['sendPduHandle'] = self.__cacheAdd(
            self.__newSendPduHandle(),
            expectResponse=kwargs.get('expectResponse')
            )

        # 4.1.1.4 & 4.1.1.5
        try:
            mpOutParams = apply(
                mpHandler.prepareOutgoingMessage, (), mpInParams
                )
        except PySnmpError:
            if mpInParams.has_key('sendPduHandle'):
                self.__cachePop(mpInParams['sendPduHandle'])
            raise
        
        # 4.1.1.6
        self.transportDispatcher.sendMessage(
            mpOutParams['wholeMsg'],
            mpOutParams['destTransportDomain'],
            mpOutParams['destTransportAddress']
            )

        # Update cache with transport details (used for retrying)
        self.__cacheUpdate(
            mpInParams['sendPduHandle'],
            wholeMsg=mpOutParams['wholeMsg'],
            destTransportDomain=mpOutParams['destTransportDomain'],
            destTransportAddress=mpOutParams['destTransportAddress'],
            sendPduHandle=mpInParams['sendPduHandle']
            )

        return mpInParams['sendPduHandle']

    # 4.1.2.1
    def returnResponsePdu(self, **kwargs):
        """PDU dispatcher -- prepare and serialize a response"""
        # Extract input values and initialize defaults
        messageProcessingModel = kwargs.get(
            'messageProcessingModel', defaultMessageProcessingVersion
            )
        mpHandler = self.messageProcessingSubsystems.get(messageProcessingModel)
        if mpHandler is None:
            raise error.BadArgumentError(
                'Unknown messageProcessingModel: %s' % messageProcessingModel
                )

        # 4.1.2.2, 4.1.2.3
        # Defaults
        mpInParams = {
            'securityModel': 3,
            'securityName': 'pluto',
            'securityLevel': 'NoAuthNoPriv',
            'pduVersion': defaultMessageProcessingVersion,
            'maxSizeResponseScopedPdu': 65000,
            'messageProcessingModel': messageProcessingModel
            }
        mpInParams.update(kwargs)
        try:
            mpOutParams = apply(
                mpHandler.prepareResponseMessage, (), mpInParams
                )
        except error.ProtoError:
            return
        
        # 4.1.2.4
        self.transportDispatcher.sendMessage(
            mpOutParams['wholeMsg'],
            mpOutParams['destTransportDomain'],
            mpOutParams['destTransportAddress']
            )

    # 4.2.1    
    def receiveMessage(
        self, tspDsp, transportDomain, transportAddress, wholeMsg
        ):
        """Message dispatcher -- de-serialize message into PDU"""
        # 4.2.1.1
        snmpInPkts, = self.mibInstrumController.mibBuilder.importSymbols(
            'SNMPv2-MIB', 'snmpInPkts'
            )
        snmpInPkts.syntax.inc(1)

        # 4.2.1.2
        try:
            restOfMsg = self.__msgDemuxer.decodeItem(wholeMsg)
        except PySnmpError:
            snmpInAsn1ParseErrs, = self.mibInstrumController.mibBuilder.importSymbols('SNMPv2-MIB', 'snmpInAsn1ParseErrs')
            snmpInAsn1ParseErrs.syntax.inc(1)
            return ''  # n.b the whole buffer gets dropped
        messageProcessingModel = self.__msgDemuxer['version'].get()
        mpHandler = self.messageProcessingSubsystems.get(
            messageProcessingModel
            )
        if mpHandler is None:
            snmpInBadVersions, = self.mibInstrumController.mibBuilder.importSymbols(
                'SNMPv2-MIB', 'snmpInBadVersions'
                )
            snmpInBadVersions.syntax.inc(1)
            return restOfMsg

        # 4.2.1.3 -- no-op

        # 4.2.1.4
        try:
            mpOutParams = mpHandler.prepareDataElements(
                transportDomain=transportDomain,
                transportAddress=transportAddress,
                wholeMsg=wholeMsg
                )
        except error.ProtoError:
            return restOfMsg        

        # 4.2.2
        if mpOutParams.get('sendPduHandle') is None:
            # 4.2.2.1 (request or notification)

            # 4.2.2.1.1
            app = self.getRegisteredApp(
                mpOutParams['contextEngineID'],
                mpOutParams['pduVersion'],
                mpOutParams['pduType']
                )

            # 4.2.2.1.2
            if app is None:
                # 4.2.2.1.2.a
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax.inc(1)

                # 4.2.2.1.2.b                
                statusInformation = {
                    'oid': snmpUnknownPDUHandlers.name,
                    'value': snmpUnknownPDUHandlers.syntax
                    }

                mpInParams = {
                    'transportDomain': transportDomain,
                    'transportAddress': transportAddress
                    }
                mpInParams.update(mpOutParams)
                mpInParams['statusInformation'] = statusInformation
                try:
                    mpOutParams = apply(
                        mpHandler.prepareResponseMessage, (), mpInParams
                        )
                except error.ProtoError:
                    return restOfMsg
                if mpOutParams.get('result'): # XXX need this?
                    return restOfMsg
                
                # 4.2.2.1.2.c
                try:
                    self.transportDispatcher.sendMessage(
                        mpOutParams['wholeMsg'],
                        mpOutParams['destTransportDomain'],
                        mpOutParams['destTransportAddress']
                        )
                except PySnmpError:
                    pass

                # 4.2.2.1.2.d
                return restOfMsg
            else:
                # 4.2.2.1.3
                apply(app.processPdu, (self,), mpOutParams)
                return restOfMsg
        else:
            # 4.2.2.2 (response)
            
            # 4.2.2.2.1
            cachedParams = self.__cachePop(mpOutParams.get('sendPduHandle'))

            # 4.2.2.2.2
            if cachedParams is None:
                snmpUnknownPDUHandlers, = self.mibInstrumController.mibBuilder.importSymbols('SNMP-MPD-MIB', 'snmpUnknownPDUHandlers')
                snmpUnknownPDUHandlers.syntax.inc(1)
                return restOfMsg

            # 4.2.2.2.3
            # no-op ? XXX

            # 4.2.2.2.4
            apply(cachedParams['expectResponse'].processResponsePdu,
                  (self,), mpOutParams)

            return restOfMsg

    # Cache expiration stuff

    def __receiveTimerTick(self, timeNow):
        def retryRequest(cachedParams, self=self, timeNow=timeNow):
            # Initialize retry params
            if not cachedParams.has_key('retryCount'):
                # Default retry params to transport-specific values
                tsp = self.transportDispatcher.getTransport(
                    cachedParams['destTransportDomain']
                    )
                cachedParams['retryCount']=tsp.retryCount
                cachedParams['retryInterval']=tsp.retryInterval
                # Initialize retry params from MIB table
                snmpTargetAddrTAddress, \
                snmpTargetAddrTDomain, \
                snmpTargetAddrRetryCount, \
                snmpTargetAddrTimeout = self.mibInstrumController.mibBuilder.importSymbols(
                    'SNMP-TARGET-MIB',
                    'snmpTargetAddrTAddress',
                    'snmpTargetAddrTDomain',
                    'snmpTargetAddrRetryCount',
                    'snmpTargetAddrTimeout'
                    )
                mibNodeIdx = snmpTargetAddrTAddress
                while 1:
                    try:
                        mibNodeIdx = snmpTargetAddrTAddress.getNextNode(
                            mibNodeIdx.name
                            )
                    except NoSuchInstanceError:
                        break
                    if mibNodeIdx.syntax != cachedParams.get(
                        'destTransportAddress'
                        ): continue
                    instId = mibNodeIdx.name[len(snmpTargetAddrTAddress.name):]
                    mibNode = snmpTargetAddrTDomain.getNode(
                        snmpTargetAddrTDomain.name + instId
                        )
                    if mibNode.syntax != cachedParams.get(
                        'destTransportDomain'
                        ): continue
                    cachedParams['retryCount'] = snmpTargetAddrRetryCount.getNode(snmpTargetAddrRetryCount.name + instId)
                    cachedParams['retryInterval'] = snmpTargetAddrTimeout.getNode(snmpTargetAddrTimeout.name + instId)
                    break                
            # Fail timed-out requests
            if cachedParams['retryCount'] == 0:
                cachedParams['expectResponse'].processResponsePdu(
                    self,
                    statusInformation = {
                    'errorIndication': error.RequestTimeout()
                    },
                    sendPduHandle=cachedParams['sendPduHandle']
                    )
                return 1
            # Re-calculate resend time
            if not cachedParams.has_key('__lastRetryTime'):
                cachedParams['__lastRetryTime'] = timeNow + \
                                                  cachedParams['retryInterval']
            if cachedParams['__lastRetryTime'] > timeNow:
                return
            # Update retry params
            cachedParams['__lastRetryTime'] = timeNow + \
                                              cachedParams['retryInterval']
            cachedParams['retryCount'] = cachedParams['retryCount'] - 1
            # Re-send request message
            try:
                self.transportDispatcher.sendMessage(
                    cachedParams['wholeMsg'],
                    cachedParams['destTransportDomain'],
                    cachedParams['destTransportAddress']
                    )
            except PySnmpError:
                pass

        self.__cacheExpire(retryRequest)

    # XXX
    receiveTimerTick = __receiveTimerTick
    
if __name__ == '__main__':
    from pysnmp.proto import rfc1157, rfc3411

    class ManagerApplication(AbstractApplication):
        def sendReq(self, dsp):
            sendPduHandle = dsp.sendPdu(
                transportDomain='udp',
                transportAddress=('127.0.0.1', 1161),
                securityName='mynmsname',
                PDU=rfc1157.GetRequestPdu(),
                expectResponse=self
                )
            
        def processResponsePdu(self, dsp, **kwargs):
            print self, repr(kwargs)
            raise "STOP"

    class AgentApplication(AbstractApplication):
        pduTypes = ((rfc1157.Version().get(), rfc1157.GetRequestPdu.tagSet),)
        def processPdu(self, dsp, **kwargs):
            print self, repr(kwargs)

            pdu = rfc1157.GetResponsePdu()
            pdu['request_id'].set(kwargs['PDU']['request_id'])
            
            # Send response
            dsp.returnResponsePdu(
                PDU=pdu,
                stateReference=kwargs['stateReference']
                )
            
    tspDsp = AsynsockDispatcher(
        udp=UdpSocketTransport().openClientMode(),
        udpd=UdpSocketTransport().openServerMode(('127.0.0.1', 1161)),
            )
    
    dsp = MsgAndPduDispatcher(transportDispatcher=tspDsp)

    snmpCommunityEntry, = dsp.mibInstrumController.mibBuilder.importSymbols(
        'SNMP-COMMUNITY-MIB', 'snmpCommunityEntry'
        )
    dsp.mibInstrumController.writeVars(
        (snmpCommunityEntry.getInstNameByIndex(2, 'mynms'), 'mycomm'),
        (snmpCommunityEntry.getInstNameByIndex(3, 'mynms'), 'mynmsname'),
        # XXX register ContextEngineIds
    )

    dsp.registerContextEngineId(AgentApplication())

    ManagerApplication().sendReq(dsp)

    try:
        dsp.transportDispatcher.runDispatcher()
    except "STOP":
        dsp.unregisterTransportDispatcher()
    
# XXX
# LCD may be used to cache frequently accessed MIB variables
# message version ID <-> MP IDs rewriting (PDU req-id re-write for v1/2 MPM)
# rework cache expiration to index ents to be expired
# rework transport in a loadable fashion
