"""Command Generator Application (SET)"""
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api
from time import time

# Protocol version to use
pMod = api.protoModules[api.protoVersion1]

# Build PDU
reqPDU =  pMod.SetRequestPDU()
pMod.apiPDU.setDefaults(reqPDU)
pMod.apiPDU.setVarBinds(
    reqPDU,
    # A list of Var-Binds to SET
    (((1,3,6,1,2,1,1,1,0), pMod.Integer(123456)),
     ((1,3,6,1,2,1,1,2,0), pMod.IPAddress('127.0.0.1')))
    )

# Build message
reqMsg = pMod.Message()
pMod.apiMessage.setDefaults(reqMsg)
pMod.apiMessage.setCommunity(reqMsg, 'public')
pMod.apiMessage.setPDU(reqMsg, reqPDU)

def cbTimerFun(timeNow, startedAt=time()):
    if timeNow - startedAt > 3:
        raise "Request timed out"
    
def cbRecvFun(tspDsp, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        print rspMsg.prettyPrinter()        
        rspPDU = pMod.apiMessage.getPDU(rspMsg)
        # Match response to request
        if pMod.apiPDU.getRequestID(reqPDU)==pMod.apiPDU.getRequestID(rspPDU):
            errorStatus = pMod.apiPDU.getErrorStatus(rspPDU)
            if errorStatus:
                print 'Error: ', errorStatus
            else:
                for oid, val in pMod.apiPDU.getVarBinds(rspPDU):
                    print oid, val
    tspDsp.doDispatchFlag = 0
    return wholeMsg

dsp = AsynsockDispatcher(udp=UdpSocketTransport().openClientMode())
dsp.registerRecvCbFun(cbRecvFun)
dsp.registerTimerCbFun(cbTimerFun)
#dsp.sendMessage(encoder.encode(reqMsg), 'udp', ('localhost', 1161)) # 161
dsp.sendMessage(encoder.encode(reqMsg), 'udp', ('ts29.moscow.net.rol.ru', 161)) # 161
dsp.runDispatcher(liveForever=1)
