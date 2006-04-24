# GETNEXT Command Generator
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
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
    reqPDU, map(lambda x, pMod=pMod: (x, pMod.Null('')), headVars)
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

def cbRecvFun(transportDispatcher, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU, headVars=headVars):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        rspPDU = pMod.apiMessage.getPDU(rspMsg)
        # Match response to request
        if pMod.apiPDU.getRequestID(reqPDU)==pMod.apiPDU.getRequestID(rspPDU):
            # Check for SNMP errors reported
            errorStatus = pMod.apiPDU.getErrorStatus(rspPDU)
            if errorStatus and errorStatus != 2:
                raise errorStatus
            # Format var-binds table
            varBindTable = pMod.apiPDU.getVarBindTable(reqPDU, rspPDU)
            # Report SNMP table
            for tableRow in varBindTable:
                for name, val in tableRow:
                    if val is None:
                        continue
                    print 'from: %s, %s = %s' % (
                        transportAddress, name.prettyPrint(), val.prettyPrint()
                        )
            # Stop on EOM
            for oid, val in varBindTable[-1]:
                if val is not None:
                    break
            else:
                transportDispatcher.jobFinished(1)
                
            # Generate request for next row
            pMod.apiPDU.setVarBinds(
                reqPDU, map(lambda (x,y),n=pMod.Null(''): (x,n), varBindTable[-1])
                )
            pMod.apiPDU.setRequestID(reqPDU, pMod.getNextRequestID())
            transportDispatcher.sendMessage(
                encoder.encode(reqMsg), transportDomain, transportAddress
                )
            global startedAt
            if time() - startedAt > 3:
                raise 'Request timed out'
            startedAt = time()
    return wholeMsg

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openClientMode()
    )
transportDispatcher.registerRecvCbFun(cbRecvFun)
transportDispatcher.registerTimerCbFun(cbTimerFun)
transportDispatcher.sendMessage(
    encoder.encode(reqMsg), udp.domainName, ('localhost', 161)
    )
transportDispatcher.jobStarted(1)
transportDispatcher.runDispatcher()
transportDispatcher.closeDispatcher()
