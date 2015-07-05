from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.proto import api
from pyasn1.codec.ber import encoder, decoder
from time import time

# Send request message to this address
transportAddress = udp.UdpTransportAddress(('195.218.195.228', 161))

# Send request message from this non-local (!) IP address
transportAddress.setLocalAddress(('1.2.3.4', 0))

# Protocol version to use
#pMod = api.protoModules[api.protoVersion1]
pMod = api.protoModules[api.protoVersion2c]

# Build PDU
reqPDU =  pMod.GetRequestPDU()
pMod.apiPDU.setDefaults(reqPDU)
pMod.apiPDU.setVarBinds(
    reqPDU, ( ('1.3.6.1.2.1.1.1.0', pMod.Null('')),
              ('1.3.6.1.2.1.1.3.0', pMod.Null('')) )
    )

# Build message
reqMsg = pMod.Message()
pMod.apiMessage.setDefaults(reqMsg)
pMod.apiMessage.setCommunity(reqMsg, 'public')
pMod.apiMessage.setPDU(reqMsg, reqPDU)

startedAt = time()

class StopWaiting(Exception): pass

def cbTimerFun(timeNow):
    if timeNow - startedAt > 3:
        raise StopWaiting()
    
def cbRecvFun(transportDispatcher, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        rspPDU = pMod.apiMessage.getPDU(rspMsg)
        # Match response to request
        if pMod.apiPDU.getRequestID(reqPDU)==pMod.apiPDU.getRequestID(rspPDU):
            # Check for SNMP errors reported
            errorStatus = pMod.apiPDU.getErrorStatus(rspPDU)
            if errorStatus:
                print(errorStatus.prettyPrint())
            else:
                for oid, val in pMod.apiPDU.getVarBinds(rspPDU):
                    print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
            transportDispatcher.jobFinished(1)
    return wholeMsg

transportDispatcher = AsyncoreDispatcher()

transportDispatcher.registerRecvCbFun(cbRecvFun)
transportDispatcher.registerTimerCbFun(cbTimerFun)

# Initialize UDP/IPv4 transport
udpSocketTransport = udp.UdpSocketTransport().openClientMode()

# Use sendmsg()/recvmsg() for socket communication (required for
# IP source spoofing functionality)
udpSocketTransport.enablePktInfo()

# Enable IP source spoofing (requires root privileges)
udpSocketTransport.enableTransparent()

transportDispatcher.registerTransport(udp.domainName, udpSocketTransport)

# Pass message to dispatcher
transportDispatcher.sendMessage(
    encoder.encode(reqMsg), udp.domainName, transportAddress
)

# We might never receive any response as we sent request with fake source IP
transportDispatcher.jobStarted(1)

# Dispatcher will finish as all jobs counter reaches zero
try:
    transportDispatcher.runDispatcher()
except StopWaiting:
    transportDispatcher.closeDispatcher()
else:
    raise
