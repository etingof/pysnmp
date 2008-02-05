# SNMP engine
from pysnmp.proto.rfc3412 import MsgAndPduDispatcher
from pysnmp.proto.mpmod.rfc2576 import SnmpV1MessageProcessingModel, \
     SnmpV2cMessageProcessingModel
from pysnmp.proto.mpmod.rfc3412 import SnmpV3MessageProcessingModel
from pysnmp.proto.secmod.rfc2576 import SnmpV1SecurityModel, \
     SnmpV2cSecurityModel
from pysnmp.proto.secmod.rfc3414 import SnmpUSMSecurityModel
from pysnmp.proto.acmod import rfc3415
from pysnmp import error

class SnmpEngine:
    def __init__(self, snmpEngineID=None, maxMessageSize=65507,
                 msgAndPduDsp=None):
        if msgAndPduDsp is None:
            self.msgAndPduDsp = MsgAndPduDispatcher()
        else:
            self.msgAndPduDsp = msgAndPduDsp
        self.messageProcessingSubsystems = {
            SnmpV1MessageProcessingModel.messageProcessingModelID:
            SnmpV1MessageProcessingModel(),
            SnmpV2cMessageProcessingModel.messageProcessingModelID:
            SnmpV2cMessageProcessingModel(),
            SnmpV3MessageProcessingModel.messageProcessingModelID:
            SnmpV3MessageProcessingModel()
            }
        self.securityModels = {
            SnmpV1SecurityModel.securityModelID: SnmpV1SecurityModel(),
            SnmpV2cSecurityModel.securityModelID: SnmpV2cSecurityModel(),
            SnmpUSMSecurityModel.securityModelID: SnmpUSMSecurityModel()
            }
        self.accessControlModel = {
            rfc3415.accessModelID: rfc3415
            }
        
        self.transportDispatcher = None
        
        if self.msgAndPduDsp.mibInstrumController is None:
            raise error.PySnmpError(
                'MIB instrumentation does not yet exist'
                )
        snmpEngineMaxMessageSize, = self.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineMaxMessageSize')
        snmpEngineMaxMessageSize.syntax = snmpEngineMaxMessageSize.syntax.clone(maxMessageSize)
        snmpEngineBoots, = self.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineBoots')
        snmpEngineBoots.syntax = snmpEngineBoots.syntax + 1        
        if snmpEngineID is not None:
            origSnmpEngineID, = self.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
            origSnmpEngineID.syntax = origSnmpEngineID.syntax.clone(snmpEngineID)

    # Transport dispatcher bindings
    
    def __receiveMessageCbFun(
        self,
        transportDispatcher,
        transportDomain,
        transportAddress,
        wholeMsg
        ):
        self.msgAndPduDsp.receiveMessage(
            self, transportDomain, transportAddress, wholeMsg
            )
                                         
    def __receiveTimerTickCbFun(self, timeNow):
        self.msgAndPduDsp.receiveTimerTick(self, timeNow)
        for mpHandler in self.messageProcessingSubsystems.values():
            mpHandler.receiveTimerTick(self, timeNow)
        for smHandler in self.securityModels.values():
            smHandler.receiveTimerTick(self, timeNow)
        
    def registerTransportDispatcher(self, transportDispatcher):
        if self.transportDispatcher is not None:
            raise error.ProtocolError(
                'Transport dispatcher already registered'
                )
        transportDispatcher.registerRecvCbFun(
            self.__receiveMessageCbFun
            )
        transportDispatcher.registerTimerCbFun(
            self.__receiveTimerTickCbFun
            )        
        self.transportDispatcher = transportDispatcher

    def unregisterTransportDispatcher(self):
        if self.transportDispatcher is None:
            raise error.ProtocolError(
                'Transport dispatcher not registered'
                )
        self.transportDispatcher.unregisterRecvCbFun()
        self.transportDispatcher.unregisterTimerCbFun()
        self.transportDispatcher = None
