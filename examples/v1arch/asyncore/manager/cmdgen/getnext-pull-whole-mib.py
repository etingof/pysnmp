"""Command Generator Application (GETNEXT)"""
from pysnmp import setApiVersion
setApiVersion('v4')
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pysnmp.proto import omni
from time import time

# Protocol version to use
ver = omni.protoVersions[omni.protoVersionId1]

# SNMP table header
headVars = [ ver.ObjectName((1,3,6)) ]

# Create request & response message objects
req = ver.Message(); rsp = ver.Message()
req.omniSetCommunity('public')

# Create PDU, load var-binds, attach PDU to SNMP message
req.omniSetPdu(ver.GetNextRequestPdu())
apply(req.omniGetPdu().omniSetVarBindList,
      map(lambda x, ver=ver: (x.get(), ver.Null()), headVars))

def cbTimerFun(timeNow, startedAt=time()):
    if timeNow - startedAt > 3:
        raise "Request timed out"
    
def cbRecvFun(tspDsp, transportDomain, transportAddress, wholeMsg,
              req=req, headVars=headVars):
    rsp = ver.Message()
    while wholeMsg:
        wholeMsg = rsp.berDecode(wholeMsg)
        if req.omniMatch(rsp):
            # Check for SNMP errors reported
            errorStatus = rsp.omniGetPdu().omniGetErrorStatus()
            if errorStatus and errorStatus != 2:
                raise errorStatus
       
            # Build SNMP table from response
            tableIndices = apply(req.omniGetPdu().omniGetTableIndices,
                                 [rsp.omniGetPdu()] + headVars)

            # Report SNMP table
            varBindList = rsp.omniGetPdu().omniGetVarBindList()
            for rowIndices in tableIndices:
                for cellIdx in filter(lambda x: x!=-1, rowIndices):
                    print transportAddress, \
                          varBindList[cellIdx].omniGetOidVal()

            # Remove completed SNMP table columns
            map(lambda idx, headVars=headVars: headVars.__delitem__(idx), \
                filter(lambda x: x==-1, tableIndices[-1]))
            if not headVars:
                raise "EOM"

            # Generate request for next row
            lastRow = map(lambda cellIdx, varBindList=varBindList:
                          varBindList[cellIdx].omniGetOidVal(),
                          filter(lambda x: x!=-1, tableIndices[-1]))
            apply(req.omniGetPdu().omniSetVarBindList,
                  map(lambda (x, y): (x.get(), None), lastRow))
        
            req.omniGetPdu().omniGetRequestId().inc(1)
            tspDsp.sendMessage(
                req.berEncode(), transportDomain, transportAddress
                ) 
    return wholeMsg

dsp = AsynsockDispatcher(udp=UdpSocketTransport().openClientMode())
dsp.registerRecvCbFun(cbRecvFun)
dsp.registerTimerCbFun(cbTimerFun)
dsp.sendMessage(req.berEncode(), 'udp', ('localhost', 1161)) # 161
dsp.runDispatcher(liveForever=1)
