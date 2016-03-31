"""
Broadcast SNMP message (IPv4)
+++++++++++++++++++++++++++++

Send SNMP GET request to broadcast address and wait for respons(es):

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to all Agents via broadcast address 255.255.255.255:161
* for OIDs in tuple form

Here we send out a single SNMP request and wait for potentially many SNMP 
responses from multiple SNMP Agents listening in local broadcast domain.
Since we can't predict the exact number of Agents responding, this script 
just waits for arbitrary time for collecting all responses. This technology
is also known as SNMP-based discovery.

This script performs similar to the following Net-SNMP command:

| $ snmpget -v2c -c public -ObentU 255.255.255.255 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0

"""#
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api
from time import time

# Broadcast manager settings
maxWaitForResponses = 5
maxNumberResponses = 10

# Protocol version to use
# pMod = api.protoModules[api.protoVersion1]
pMod = api.protoModules[api.protoVersion2c]

# Build PDU
reqPDU = pMod.GetRequestPDU()
pMod.apiPDU.setDefaults(reqPDU)
pMod.apiPDU.setVarBinds(
    reqPDU, (('1.3.6.1.2.1.1.1.0', pMod.Null('')),
             ('1.3.6.1.2.1.1.3.0', pMod.Null('')))
)

# Build message
reqMsg = pMod.Message()
pMod.apiMessage.setDefaults(reqMsg)
pMod.apiMessage.setCommunity(reqMsg, 'public')
pMod.apiMessage.setPDU(reqMsg, reqPDU)

startedAt = time()


class StopWaiting(Exception): pass


def cbTimerFun(timeNow):
    if timeNow - startedAt > maxWaitForResponses:
        raise StopWaiting()


# noinspection PyUnusedLocal,PyUnusedLocal
def cbRecvFun(transportDispatcher, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        rspPDU = pMod.apiMessage.getPDU(rspMsg)
        # Match response to request
        if pMod.apiPDU.getRequestID(reqPDU) == pMod.apiPDU.getRequestID(rspPDU):
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

# UDP/IPv4
udpSocketTransport = udp.UdpSocketTransport().openClientMode().enableBroadcast()
transportDispatcher.registerTransport(udp.domainName, udpSocketTransport)

# Pass message to dispatcher
transportDispatcher.sendMessage(
    encoder.encode(reqMsg), udp.domainName, ('255.255.255.255', 161)
)

# wait for a maximum of 10 responses or time out
transportDispatcher.jobStarted(1, maxNumberResponses)

# Dispatcher will finish as all jobs counter reaches zero
try:
    transportDispatcher.runDispatcher()
except StopWaiting:
    transportDispatcher.closeDispatcher()
else:
    raise
