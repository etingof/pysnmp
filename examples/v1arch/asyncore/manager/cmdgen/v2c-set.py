"""Command Generator Application (GET)"""
from time import time
from pysnmp import setApiVersion
setApiVersion('v4')
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pysnmp.proto.api import alpha

# Protocol version to use
ver = alpha.protoVersions[alpha.protoVersionId1]

# Build message
req = ver.Message()
req.apiAlphaSetCommunity('public')

# Build PDU
req.apiAlphaSetPdu(ver.SetRequestPdu())
req.apiAlphaGetPdu().apiAlphaSetVarBindList(
    # A list of Var-Binds to SET
    ((1,3,6,1,2,1,1,1,0), ver.Integer(123456)),
    ((1,3,6,1,2,1,1,1,0), ver.IpAddress('127.0.0.1'))
    )

def cbTimerFun(timeNow, startedAt=time()):
    if timeNow - startedAt > 3:
        raise "Request timed out"
    
def cbRecvFun(tspDsp, transportDomain, transportAddress, wholeMsg, req=req):
    rsp = ver.Message()
    while wholeMsg:
        wholeMsg = rsp.berDecode(wholeMsg)

        # Make sure this is a response to this request
        if req.apiAlphaMatch(rsp):
            errorStatus = rsp.apiAlphaGetPdu().apiAlphaGetErrorStatus()
            if errorStatus:
                print 'Error: ', errorStatus
            else:
                for varBind in rsp.apiAlphaGetPdu().apiAlphaGetVarBindList():
                    print varBind.apiAlphaGetOidVal()
    tspDsp.doDispatchFlag = 0
    return wholeMsg

dsp = AsynsockDispatcher(udp=UdpSocketTransport().openClientMode())
dsp.registerRecvCbFun(cbRecvFun)
dsp.registerTimerCbFun(cbTimerFun)
dsp.sendMessage(req.berEncode(), 'udp', ('localhost', 1161)) # 161
dsp.runDispatcher(liveForever=1)
