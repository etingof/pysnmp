"""
Spoof IPv4 source address
+++++++++++++++++++++++++

Send SNMP GET request from a non-local IP address:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at 195.218.195.228:161
* from a non-local, spoofed IP 1.2.3.4 (root and Python 3.3+ required)
* for OIDs in string form

This script performs similar to the following Net-SNMP command:

| $ snmpget -v2c -c public -ObentU 195.218.195.228 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0

But unlike the above command, this script issues SNMP request from a 
non-default, non-local IP address.

It is indeed possible to originate SNMP traffic from any valid local IP 
addresses. It could be a secondary IP interface, for instance. Superuser 
privileges are only required to send spoofed packets. Alternatively, 
sending from local interface could also be achieved by binding to 
it (via openClientMode() parameter).

Agent would respond to the IP address you used as a source. So this script 
could only get a response if that source address is somehow routed to the 
host this script is running on. Otherwise it just times out.

"""#
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
