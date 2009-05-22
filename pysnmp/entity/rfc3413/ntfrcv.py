from pysnmp.proto import rfc3411, error
from pysnmp.proto.api import v1, v2c  # backend is always SMIv2 compliant
from pysnmp.proto.proxy import rfc2576

# 3.4
class NotificationReceiver:
    pduTypes = (
        v1.TrapPDU.tagSet,        
        v2c.SNMPv2TrapPDU.tagSet,
        v2c.InformRequestPDU.tagSet
        )

    def __init__(self, snmpEngine, cbFun, cbCtx=None):
        snmpEngine.msgAndPduDsp.registerContextEngineId(
            '', self.pduTypes, self.processPdu # '' is a wildcard
            )
        self.__cbFunVer = 0
        self.__cbFun = cbFun
        self.__cbCtx = cbCtx

    def close(self, snmpEngine):
        snmpEngine.msgAndPduDsp.unregisterContextEngineId(
            '', self.pduTypes
            )

    def processPdu(
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
        maxSizeResponseScopedPDU,
        stateReference
        ):

        # Agent-side API complies with SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1ToV2(PDU)

        errorStatus = 'noError'; errorIndex = 0
        varBinds = v2c.apiPDU.getVarBinds(PDU)
        
        # 3.4
        if rfc3411.confirmedClassPDUs.has_key(PDU.tagSet):
            # 3.4.1 --> no-op
            
            rspPDU = v2c.apiPDU.getResponse(PDU)
            
            # 3.4.2
            v2c.apiPDU.setErrorStatus(rspPDU, errorStatus)
            v2c.apiPDU.setErrorIndex(rspPDU, errorIndex)
            v2c.apiPDU.setVarBinds(rspPDU, varBinds)

            # Agent-side API complies with SMIv2
            if messageProcessingModel == 0:
                rspPDU = rfc2576.v2ToV1(rspPDU)

            statusInformation = {}
            
            # 3.4.3
            try:
                snmpEngine.msgAndPduDsp.returnResponsePdu(
                    snmpEngine,
                    messageProcessingModel,
                    securityModel,
                    securityName,
                    securityLevel,
                    contextEngineId,
                    contextName,
                    pduVersion,
                    rspPDU,
                    maxSizeResponseScopedPDU,
                    stateReference,
                    statusInformation
                    )
            except error.StatusInformation:
                snmpSilentDrops, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpSilentDrops')
                snmpSilentDrops.syntax = snmpSilentDrops.syntax + 1

        elif rfc3411.unconfirmedClassPDUs.has_key(PDU.tagSet):
            pass
        else:
            raise error.ProtocolError('Unexpected PDU class %s' % PDU.tagSet)

        if self.__cbFunVer:
            self.__cbFun(
                snmpEngine, stateReference, contextEngineId, contextName,
                varBinds, self.__cbCtx
                )
        else:
            # Compatibility stub (handle legacy cbFun interface)
            try:
                self.__cbFun(
                    snmpEngine, contextEngineId, contextName,
                    varBinds, self.__cbCtx
                    )
            except TypeError:
                self.__cbFunVer = 1
                self.__cbFun(
                    snmpEngine, stateReference, contextEngineId, contextName,
                    varBinds, self.__cbCtx
                    )
