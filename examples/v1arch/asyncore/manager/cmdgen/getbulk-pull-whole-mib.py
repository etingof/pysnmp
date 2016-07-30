"""
Bulk walk Agent MIB (SNMPv2c)
+++++++++++++++++++++++++++++

Perform SNMP GETBULK operation with the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for OID in tuple form
* with non-repeaters=0 and max-repeaters=25

This script performs similar to the following Net-SNMP command:

| $ snmpbulkwalk -v2c -c public -ObentU -Cn0 -Cr25 demo.snmplabs.com 1.3.6

"""#
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto.api import v2c
from time import time

# SNMP table header
headVars = [v2c.ObjectIdentifier((1, 3, 6))]

# Build PDU
reqPDU = v2c.GetBulkRequestPDU()
v2c.apiBulkPDU.setDefaults(reqPDU)
v2c.apiBulkPDU.setNonRepeaters(reqPDU, 0)
v2c.apiBulkPDU.setMaxRepetitions(reqPDU, 25)
v2c.apiBulkPDU.setVarBinds(reqPDU, [(x, v2c.null) for x in headVars])

# Build message
reqMsg = v2c.Message()
v2c.apiMessage.setDefaults(reqMsg)
v2c.apiMessage.setCommunity(reqMsg, 'public')
v2c.apiMessage.setPDU(reqMsg, reqPDU)

startedAt = time()


def cbTimerFun(timeNow):
    if timeNow - startedAt > 3:
        raise Exception("Request timed out")


# noinspection PyUnusedLocal
def cbRecvFun(transportDispatcher, transportDomain, transportAddress,
              wholeMsg, reqPDU=reqPDU, headVars=headVars):
    while wholeMsg:
        rspMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=v2c.Message())

        rspPDU = v2c.apiMessage.getPDU(rspMsg)

        # Match response to request
        if v2c.apiBulkPDU.getRequestID(reqPDU) == v2c.apiBulkPDU.getRequestID(rspPDU):
            # Format var-binds table
            varBindTable = v2c.apiBulkPDU.getVarBindTable(reqPDU, rspPDU)

            # Check for SNMP errors reported
            errorStatus = v2c.apiBulkPDU.getErrorStatus(rspPDU)
            if errorStatus and errorStatus != 2:
                errorIndex = v2c.apiBulkPDU.getErrorIndex(rspPDU)
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBindTable[int(errorIndex) - 1] or '?'))
                transportDispatcher.jobFinished(1)
                break

            # Report SNMP table
            for tableRow in varBindTable:
                for name, val in tableRow:
                    print('from: %s, %s = %s' % (
                        transportAddress, name.prettyPrint(), val.prettyPrint()
                    )
                          )

            # Stop on EOM
            for oid, val in varBindTable[-1]:
                if not isinstance(val, v2c.Null):
                    break
            else:
                transportDispatcher.jobFinished(1)

            # Generate request for next row
            v2c.apiBulkPDU.setVarBinds(
                reqPDU, [(x, v2c.null) for x, y in varBindTable[-1]]
            )
            v2c.apiBulkPDU.setRequestID(reqPDU, v2c.getNextRequestID())
            transportDispatcher.sendMessage(
                encoder.encode(reqMsg), transportDomain, transportAddress
            )
            global startedAt
            if time() - startedAt > 3:
                raise Exception('Request timed out')
            startedAt = time()
    return wholeMsg


transportDispatcher = AsyncoreDispatcher()

transportDispatcher.registerRecvCbFun(cbRecvFun)
transportDispatcher.registerTimerCbFun(cbTimerFun)

transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openClientMode()
)
transportDispatcher.sendMessage(
    encoder.encode(reqMsg), udp.domainName, ('demo.snmplabs.com', 161)
)
transportDispatcher.jobStarted(1)

# Dispatcher will finish as job#1 counter reaches zero
transportDispatcher.runDispatcher()

transportDispatcher.closeDispatcher()
