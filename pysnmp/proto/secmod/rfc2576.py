# SNMP v1 & v2c security models implementation
from pysnmp.proto.secmod import base, error
from pysnmp.proto import rfc1157, rfc1905, rfc3411
from pysnmp.smi.error import NoSuchInstanceError

__all__ = [ 'SnmpV1SecurityModel', 'SnmpV2cSecurityModel' ]

class SnmpV1SecurityModel(base.AbstractSecurityModel):
    # Map PDU to PDU key names at PDUS choice
    _pduMap = {
        # SNMP v1
        rfc1157.GetRequestPdu.tagSet: 'get_request',
        rfc1157.GetNextRequestPdu.tagSet: 'get_next_request',
        rfc1157.GetResponsePdu.tagSet: 'get_response',
        rfc1157.SetRequestPdu.tagSet: 'set_request',
        rfc1157.TrapPdu.tagSet: 'trap',
        }

    _protoMsg = rfc1157.Message
    def __init__(self, mibInstrumController=None):
        base.AbstractSecurityModel.__init__(self, mibInstrumController)
        self.__msg = self._protoMsg()
        
    # According to rfc2576, community name <-> contextEngineID/contextName
    # mapping is up to MP module for notifications but belongs to secmod
    # responsibility for other PDU types. Since I do not yet understand
    # the reason for such distribution, I moved this code from MP-scope
    # in here.

    def generateRequestMsg(self, **kwargs):
        # rfc2576: 5.2.3
        snmpCommunityName, \
        snmpCommunitySecurityName, \
        snmpCommunityContextEngineID, \
        snmpCommunityContextName = self.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName'
            )
        mibNodeIdx = snmpCommunitySecurityName
        while 1:
            try:
                mibNodeIdx = snmpCommunitySecurityName.getNextNode(
                    mibNodeIdx.name
                    )
            except NoSuchInstanceError:
                break
            if mibNodeIdx.syntax != kwargs.get('securityName'):
                continue
            instId = mibNodeIdx.name[len(snmpCommunitySecurityName.name):]
            mibNode = snmpCommunityContextEngineID.getNode(
                snmpCommunityContextEngineID.name + instId
                )
            if mibNode.syntax != kwargs.get('contextEngineID'):
                continue
            mibNode = snmpCommunityContextName.getNode(
                snmpCommunityContextName.name + instId
                )
            if mibNode.syntax != kwargs.get('contextName'):
                continue
            mibNode = snmpCommunityName.getNode(
                snmpCommunityName.name + instId
                )
            communityName = mibNode.syntax.get()
            self.__msg['community'].set(communityName)
            transportDomain, transportAddress, pdu = kwargs['scopedPDU']
            self.__msg['pdu'][self._pduMap[pdu.tagSet]] = pdu
            return {
                'securityParameters': communityName,
                'wholeMsg': self.__msg.berEncode()
                }
        raise error.BadArgumentError(
            'Can\'t resolve community name to contextEngineID/Name'
            )

    def generateResponseMsg(self, **kwargs):
        # rfc2576: 5.2.2
        securityParameters = kwargs['securityStateReference']        
        communityName = securityParameters
        self.__msg['community'].set(communityName)
        transportDomain, transportAddress, pdu = kwargs['scopedPDU']
        self.__msg['pdu'][self._pduMap[pdu.tagSet]] = pdu
        return {
            'securityParameters': securityParameters,
            'wholeMsg': self.__msg.berEncode()
            }

    def processIncomingMsg(self, **kwargs):
        self.__msg.decodeItem(kwargs['wholeMsg'])
        
        # rfc2576: 5.2.1
        transportDomain, transportAddress = kwargs.get(
            'securityParameters'
            )
        
        # According to rfc2576 this should be done at MP but I don't yet see
        # the reason why it wouldn't be better done at SM
        communityName = self.__msg['community']

        ( snmpCommunityName,
          snmpCommunitySecurityName,
          snmpCommunityContextEngineID,
          snmpCommunityContextName ) = \
          self.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-COMMUNITY-MIB',
            'snmpCommunityName',
            'snmpCommunitySecurityName',
            'snmpCommunityContextEngineID',
            'snmpCommunityContextName'
            )
        mibNodeIdx = snmpCommunityName
        while 1:
            try:
                mibNodeIdx = snmpCommunityName.getNextNode(
                    mibNodeIdx.name
                    )
            except NoSuchInstanceError:
                break
            if mibNodeIdx.syntax != communityName:
                continue
            break
        else:
            raise error.BadArgumentError(
                'No matching community name found'
                )
        instId = mibNodeIdx.name[len(snmpCommunityName.name):]
        communityName = snmpCommunityName.getNode(
            snmpCommunityName.name + instId
            )
        securityName = snmpCommunitySecurityName.getNode(
            snmpCommunitySecurityName.name + instId
            )
        contextEngineID = snmpCommunityContextEngineID.getNode(
            snmpCommunityContextEngineID.name + instId
            )
        contextName = snmpCommunityContextName.getNode(
            snmpCommunityContextName.name + instId
            )
        snmpEngineID, = self.mibInstrumController.mibBuilder.importSymbols(
            'SNMP-FRAMEWORK-MIB', 'snmpEngineID'
            )
        return {
            'securityEngineID': snmpEngineID.syntax.get(),
            'securityName': securityName.syntax.get(),
            'scopedPDU': (
            contextEngineID.syntax.get(), contextName.syntax.get(),
            self.__msg['pdu'].values()[0]
            ),
            'maxSizeResponseScopedPDU': 65000, # XXX
            'securityStateReference': communityName.syntax.get()
            }
    
class SnmpV2cSecurityModel(SnmpV1SecurityModel):
    _pduMap = {
        # SNMP v2c
        rfc1905.GetRequestPdu.tagSet: 'get_request',
        rfc1905.GetNextRequestPdu.tagSet: 'get_next_request',
        rfc1905.GetBulkRequestPdu.tagSet: 'get_bulk_request',
        rfc1905.ResponsePdu.tagSet: 'response',
        rfc1905.SetRequestPdu.tagSet: 'set_request',
        rfc1905.InformRequestPdu.tagSet: 'inform_request',
        rfc1905.SnmpV2TrapPdu.tagSet: 'snmpV2_trap',
        rfc1905.ReportPdu.tagSet: 'report'
        }
    _protoMsg = rfc1905.Message
    
if __name__ == '__main__':
    from pysnmp.proto import rfc1157
    from pysnmp.smi.objects import module

    mib = module.MibModules().loadModules()

    row = mib.getVariable((1,3,6,1,6,3,18,1,1,1))
    mib.writeVars(
        (row.getInstNameByIndex(2, 'myrouter'), 'mycomm'),
        (row.getInstNameByIndex(3, 'myrouter'), 'myrt'),
    )

    sm = SnmpV1SecurityModel(mib)
    smInParams = {
        'scopedPDU': ('', '', rfc1157.GetRequestPdu()),
        'securityName': 'myrt',
        'contextEngineID': '80004fb81c0a80101',
        'contextName': ''
        }

    smOutParams = apply(sm.generateRequestMsg, (), smInParams)
    print smOutParams

    smInParams = {
        'securityParameters': ('mycomm', '', ''),
        'wholeMsg': smOutParams['wholeMsg']
        }

    print apply(sm.processIncomingMsg, (), smInParams)    
