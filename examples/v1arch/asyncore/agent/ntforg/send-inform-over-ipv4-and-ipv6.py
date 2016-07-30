"""
INFORM over multiple transports
+++++++++++++++++++++++++++++++

The following script sends SNMP INFORM notification using the following options:

* with SNMPv2c
* with community name 'public'
* over IPv4/UDP and IPv6/UDP
* send INFORM notification
* to a Manager at demo.snmplabs.com:162 and [::1]:162
* with TRAP ID 'coldStart' specified as an OID

The following Net-SNMP command will produce similar SNMP notification:

| $ snmpinform -v2c -c public udp:demo.snmplabs.com 0 1.3.6.1.6.3.1.1.5.1
| $ snmpinform -v2c -c public udp6:[::1] 0 1.3.6.1.6.3.1.1.5.1

"""#
from time import time
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto.api import v2c as pMod

# Build PDU
reqPDU = pMod.InformRequestPDU()
pMod.apiTrapPDU.setDefaults(reqPDU)

# Build message
trapMsg = pMod.Message()
pMod.apiMessage.setDefaults(trapMsg)
pMod.apiMessage.setCommunity(trapMsg, 'public')
pMod.apiMessage.setPDU(trapMsg, reqPDU)

startedAt = time()


def cbTimerFun(timeNow):
    if timeNow - startedAt > 3:
        raise Exception("Request timed out")


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
                print('INFORM message delivered, response var-binds follow')
                for oid, val in pMod.apiPDU.getVarBinds(rspPDU):
                    print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
            transportDispatcher.jobFinished(1)
    return wholeMsg


transportDispatcher = AsynsockDispatcher()

transportDispatcher.registerRecvCbFun(cbRecvFun)
transportDispatcher.registerTimerCbFun(cbTimerFun)

# UDP/IPv4
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openClientMode()
)
transportDispatcher.sendMessage(
    encoder.encode(trapMsg), udp.domainName, ('demo.snmplabs.com', 162)
)
transportDispatcher.jobStarted(1)

# UDP/IPv6
# transportDispatcher.registerTransport(
#    udp6.domainName, udp6.Udp6SocketTransport().openClientMode()
# )
# transportDispatcher.sendMessage(
#    encoder.encode(trapMsg), udp6.domainName, ('::1', 162)
# )
# transportDispatcher.jobStarted(1)

# Dispatcher will finish as all scheduled messages are sent
transportDispatcher.runDispatcher()

transportDispatcher.closeDispatcher()
