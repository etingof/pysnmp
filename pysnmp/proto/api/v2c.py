from pysnmp.proto import rfc1902, rfc1905, error
from pysnmp.proto.api import v1
from pyasn1.type import univ, namedtype, namedval

# Shortcuts to SNMP types
Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

Integer = rfc1902.Integer
Integer32 = rfc1902.Integer32
OctetString = rfc1902.OctetString
IpAddress = rfc1902.IpAddress
Counter32 = rfc1902.Counter32
Gauge32 = rfc1902.Gauge32
Unsigned32 = rfc1902.Unsigned32
TimeTicks = rfc1902.TimeTicks
Opaque = rfc1902.Opaque
Counter64 = rfc1902.Counter64
Bits = rfc1902.Bits

VarBind = rfc1905.VarBind
VarBindList = rfc1905.VarBindList
GetRequestPDU = rfc1905.GetRequestPDU
GetNextRequestPDU = rfc1905.GetNextRequestPDU
ResponsePDU = GetResponsePDU = rfc1905.ResponsePDU
SetRequestPDU = rfc1905.SetRequestPDU
GetBulkRequestPDU = rfc1905.GetBulkRequestPDU
InformRequestPDU = rfc1905.InformRequestPDU
SNMPv2TrapPDU = TrapPDU = rfc1905.SNMPv2TrapPDU
ReportPDU = rfc1905.ReportPDU

# v2 model uses v1 messaging but it's not defined in v2 MIB
class Message(v1.Message):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues = namedval.NamedValues(('version-2', 1)))),
        namedtype.NamedType('community', univ.OctetString()),
        namedtype.NamedType('data', rfc1905.PDUs())
        )

getNextRequestID = v1.getNextRequestID

apiVarBind = v1.apiVarBind

class PDUAPI(v1.PDUAPI):
    def getResponse(self, reqPDU):
        rspPDU = ResponsePDU()
        self.setDefaults(rspPDU)
        self.setRequestID(rspPDU, self.getRequestID(reqPDU))
        return rspPDU

apiPDU = PDUAPI()

class BulkPDUAPI(PDUAPI):
    def getNonRepeaters(self, pdu): return pdu.getComponentByPosition(1)
    def setNonRepeaters(self, pdu, value): pdu.setComponentByPosition(1, value)

    def getMaxRepetitions(self, pdu): return pdu.getComponentByPosition(2)
    def setMaxRepetitions(self,pdu,value): pdu.setComponentByPosition(2,value)

    def getTableIndices(self, reqPDU, rspPDU, headerVars):
        nonRepeaters = int(self.getNonRepeaters(reqPDU))
        N = min(nonRepeaters, len(self.getVarBindList(reqPDU)))
        R = max(len(self.getVarBindList(reqPDU))-N, 0)
        if R == 0:
            M = 0
        else:
            M = int(min(self.getMaxRepetitions(reqPDU),
                        (len(apiPDU.getVarBindList(rspPDU))-N))/R)
        if len(headerVars) < R + N:
            raise error.ProtocolError('Short table header')                
        endOfMIBIndices = map(lambda (x,y):x, apiPDU.getErrorBinds(rspPDU))
        varBindList = apiPDU.getVarBindList(rspPDU)
        varBindRows = []; varBindTable = [ varBindRows ]
        for idx in range(N):
            if idx in endOfMIBIndices: # check _val XXX
                varBindRows.append(-1)
                continue
            oid, val = apiVarBind.getOIDVal(varBindList[idx])
            if not headerVars[idx].isPrefixOf(oid):
                varBindRows.append(-1)
                continue
            varBindRows.append(idx)
        for rowIdx in range(M):
            if len(varBindTable) < rowIdx+1:
                varBindTable.append([])
            varBindRow = varBindTable[-1]
            for colIdx in range(R):
                while rowIdx and len(varBindRow) < N:
                    varBindRow.append(varBindTable[-2][colIdx])
                if len(varBindRow) < colIdx+N+1:
                    varBindRow.append(-1)
                idx = N + rowIdx*R + colIdx
                oid, val = apiVarBind.getOIDVal(varBindList[idx])
                if headerVars[colIdx+N].isPrefixOf(oid):
                    varBindRow[-1] = idx
        return varBindTable

apiBulkPDU = BulkPDUAPI()

class MessageAPI(v1.MessageAPI):
    def setDefaults(self, msg):
        msg.setComponentByPosition(0, 1)
        msg.setComponentByPosition(1, 'public')
        return msg

    def getResponse(self, reqMsg):
        rspMsg = Message()
        self.setDefaults(rspMsg)
        self.setVersion(rspMsg, self.getVersion(reqMsg))
        self.setCommunity(rspMsg, self.getCommunity(reqMsg))
        self.setPDU(rspMsg, apiPDU.getResponse(self.getPDU(reqMsg)))
        return rspMsg

apiMessage = MessageAPI()
