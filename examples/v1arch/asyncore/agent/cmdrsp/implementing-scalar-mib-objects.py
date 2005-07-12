"""Command Responder Application (GETNEXT PDU)"""
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api
import time, bisect

class SysDescr:
    name = (1,3,6,1,2,1,1,1,0)
    def __cmp__(self, other): return cmp(self.name, other)    
    def __call__(self, protoVer):
        return api.protoModules[protoVer].OctetString(
            'PySNMP example command responder at %s' % __file__
            )

class Uptime:
    name = (1,3,6,1,2,1,1,3,0)
    birthday = time.time()
    def __cmp__(self, other): return cmp(self.name, other)
    def __call__(self, protoVer):
        return api.protoModules[protoVer].TimeTicks(
            (time.time()-self.birthday)*100
            )

mibInstr = (
    SysDescr(), Uptime() # sorted by object name
    )

mibInstrIdx = {}
for mibVar in mibInstr:
    mibInstrIdx[mibVar.name] = mibVar

def cbFun(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = api.decodeMessageVersion(wholeMsg)
        pMod = api.protoModules[msgVer]
        reqMsg, wholeMsg = decoder.decode(
            wholeMsg, asn1Spec=pMod.Message(),
            )
        rspMsg = pMod.apiMessage.getResponse(reqMsg)
        rspPDU = pMod.apiMessage.getPDU(rspMsg)        
        reqPDU = pMod.apiMessage.getPDU(reqMsg)
        varBinds = []; errorIndex = -1
        # GETNEXT PDU
        if reqPDU.isSameTypeWith(pMod.GetNextRequestPDU()):
            # Produce response var-binds
            errorIndex = -1
            for oid, val in pMod.apiPDU.getVarBinds(reqPDU):
                errorIndex = errorIndex + 1
                # Search next OID to report
                nextIdx = bisect.bisect(mibInstr, oid)
                if nextIdx == len(mibInstr):
                    # Out of MIB
                    pMod.apiPDU.setEndOfMibError(rspPDU, errorIndex)
                else:
                    # Report value if OID is found
                    varBinds.append(
                        (mibInstr[nextIdx].name, mibInstr[nextIdx](msgVer))
                        )
        elif reqPDU.isSameTypeWith(pMod.GetRequestPDU()):
            for oid, val in pMod.apiPDU.getVarBinds(reqPDU):
                if mibInstrIdx.has_key(oid):
                    varBinds.append(
                        (oid, mibInstrIdx[oid](msgVer))
                        )
                else:
                    # No such instance
                    pMod.apiPDU.setNoSuchInstanceError(rspPDU, errorIndex)
                    varBinds = pMod.apiPDU.getVarBinds(reqPDU)
                    break
        else:
            # Report unsupported request type
            pMod.apiPDU.setErrorStatus(rspPDU, 'genErr')
        pMod.apiPDU.setVarBinds(rspPDU, varBinds)
        transportDispatcher.sendMessage(
            encoder.encode(rspMsg), transportDomain, transportAddress
            )
    return wholeMsg

transportDispatcher = AsynsockDispatcher()
transportDispatcher.registerTransport(
    udp.domainName, udp.UdpSocketTransport().openServerMode(('localhost', 161))
    )
transportDispatcher.registerRecvCbFun(cbFun)
transportDispatcher.runDispatcher()
