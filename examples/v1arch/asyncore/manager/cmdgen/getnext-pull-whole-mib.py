"""Command Generator Application (GETNEXT)"""
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api
from time import time

# Protocol version to use
pMod = api.protoModules[api.protoVersion1]

# SNMP table header
headVars = [ pMod.ObjectIdentifier((1,3,6)) ]

# Build PDU
reqPDU =  pMod.GetNextRequestPDU()
pMod.apiPDU.setDefaults(reqPDU)
pMod.apiPDU.setVarBinds(
    reqPDU, map(lambda x, pMod=pMod: (x, pMod.Null()), headVars)
    )

# Build message
reqMsg = pMod.Message()
pMod.apiMessage.setDefaults(reqMsg)
pMod.apiMessage.setCommunity(reqMsg, 'public')
pMod.apiMessage.setPDU(reqMsg, reqPDU)

startedAt = time()

def cbTimerFun(timeNow):
    if timeNow - startedAt > 3:
        raise "Request timed out"

def cbRecvFun(tspDsp, transportDomain, transportAddress, wholeMsg,
              reqPDU=reqPDU, headVars=headVars):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
#        print rspMsg.prettyPrinter()        
        rspPDU = pMod.apiMessage.getPDU(rspMsg)
        # Match response to request
        if pMod.apiPDU.getRequestID(reqPDU)==pMod.apiPDU.getRequestID(rspPDU):
            # Check for SNMP errors reported
            errorStatus = pMod.apiPDU.getErrorStatus(rspPDU)
            if errorStatus and errorStatus != 2:
                raise errorStatus
            # Build SNMP table from response
            tableIndices = pMod.apiPDU.getTableIndices(
                reqPDU, rspPDU, headVars
                )
            # Report SNMP table
            varBindList = pMod.apiPDU.getVarBindList(rspPDU)
            for rowIndices in tableIndices:
                for cellIdx in filter(lambda x: x!=-1, rowIndices):
                    print transportAddress,
                    print pMod.apiVarBind.getOIDVal(varBindList[cellIdx])

            # Remove completed SNMP table columns
            map(lambda idx, headVars=headVars: headVars.__delitem__(idx), \
                filter(lambda x: x==-1, tableIndices[-1]))
            if not headVars:
                raise "EOM"

            # Generate request for next row
            lastRow = []
            for cellIdx in filter(lambda x: x!=-1, tableIndices[-1]):
                lastRow.append(
                    (pMod.apiVarBind.getOIDVal(varBindList[cellIdx])[0],
                     pMod.Null())
                    )
            pMod.apiPDU.setVarBinds(reqPDU, lastRow)
            pMod.apiPDU.setRequestID(reqPDU, pMod.getNextRequestID())
            tspDsp.sendMessage(
                encoder.encode(reqMsg), transportDomain, transportAddress
                )
            global startedAt
            if time() - startedAt > 3:
                raise 'Request timed out'
            startedAt = time()
    return wholeMsg

dsp = AsynsockDispatcher(udp=UdpSocketTransport().openClientMode())
dsp.registerRecvCbFun(cbRecvFun)
dsp.registerTimerCbFun(cbTimerFun)
#dsp.sendMessage(req.berEncode(), 'udp', ('localhost', 1161)) # 161
dsp.sendMessage(encoder.encode(reqMsg), 'udp', ('ts29.moscow.net.rol.ru', 161))

try:
    msgAndPduDsp.transportDispatcher.runDispatcher()
except "EOM":
    pass

#def f():
#    dsp.runDispatcher(liveForever=1)
#f()
#import profile
#profile.run('f()')
