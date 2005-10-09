"""Notification Receiver Application (TRAP PDU)"""
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

def cbFun(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))
        pMod = api.protoModules[msgVer]
        reqMsg, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=pMod.Message(),
            )
        print 'Notification message from %s:%s: ' % (
            transportDomain, transportAddress
            )
        reqPDU = pMod.apiMessage.getPDU(reqMsg)
        if reqPDU.isSameTypeWith(pMod.TrapPDU()):
            if msgVer == api.protoVersion1:
                print 'Enterprise: %s' % (
                    pMod.apiTrapPDU.getEnterprise(reqPDU)
                    )
                print 'Agent Address: %s' % (
                    repr(pMod.apiTrapPDU.getAgentAddr(reqPDU))
                    )
                print 'Generic Trap: %s' % (
                    pMod.apiTrapPDU.getGenericTrap(reqPDU)
                    )
                print 'Specific Trap: %s' % (
                    pMod.apiTrapPDU.getSpecificTrap(reqPDU)
                    )
                print 'Uptime: %s' % (
                    pMod.apiTrapPDU.getTimeStamp(reqPDU)
                    )
                print 'Var-binds:'
                for varBind in pMod.apiTrapPDU.getVarBindList(reqPDU):
                    print pMod.apiVarBind.getOIDVal(varBind)
            else:
                print 'Var-binds:'
                for varBind in pMod.apiPDU.getVarBindList(reqPDU):
                    print pMod.apiVarBind.getOIDVal(varBind)
    return wholeMsg

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openServerMode(('localhost', 1162))
    )
transportDispatcher.registerRecvCbFun(cbFun)
transportDispatcher.jobStarted(1) # this job would never finish
transportDispatcher.runDispatcher()
