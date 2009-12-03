import types
from pyasn1.type import univ
from pysnmp.proto import rfc1155, rfc1157, error
from pysnmp import nextid

# Shortcuts to SNMP types
Integer = univ.Integer
OctetString = univ.OctetString
Null = univ.Null
ObjectIdentifier = univ.ObjectIdentifier

IpAddress = rfc1155.IpAddress
NetworkAddress = rfc1155.NetworkAddress
Counter = rfc1155.Counter
Gauge = rfc1155.Gauge
TimeTicks = rfc1155.TimeTicks
Opaque = rfc1155.Opaque

VarBind = rfc1157.VarBind
VarBindList = rfc1157.VarBindList
GetRequestPDU = rfc1157.GetRequestPDU
GetNextRequestPDU = rfc1157.GetNextRequestPDU
GetResponsePDU = rfc1157.GetResponsePDU
SetRequestPDU = rfc1157.SetRequestPDU
TrapPDU = rfc1157.TrapPDU
Message = rfc1157.Message

class VarBindAPI:
    _null = Null('')
    def setOIDVal(self, varBind, (oid, val)):
        varBind.setComponentByPosition(0, oid)
        if val is None: val = self._null
        varBind.setComponentByPosition(1).getComponentByPosition(1).setComponentByType(val.getTagSet(), val, 1)
        return varBind
    
    def getOIDVal(self, varBind):
        return varBind[0], varBind[1].getComponent(1)

apiVarBind = VarBindAPI()

getNextRequestID = nextid.Integer(0xffff)

class PDUAPI:
    def setDefaults(self, pdu):
        pdu.setComponentByPosition(0, getNextRequestID())
        pdu.setComponentByPosition(1, 0)
        pdu.setComponentByPosition(2, 0)
        pdu.setComponentByPosition(3)
        
    def getRequestID(self, pdu): return pdu.getComponentByPosition(0)
    def setRequestID(self, pdu, value): pdu.setComponentByPosition(0, value)

    def getErrorStatus(self, pdu): return pdu.getComponentByPosition(1)
    def setErrorStatus(self, pdu, value): pdu.setComponentByPosition(1, value)

    def getErrorIndex(self, pdu):
        errorIndex = pdu.getComponentByPosition(2)
        if errorIndex > len(pdu[3]):
            raise error.ProtocolError(
                'Error index out of range: %s > %s' % (errorIndex, len(pdu[3]))
                )
        return errorIndex
    def setErrorIndex(self, pdu, value):
        pdu.setComponentByPosition(2, value)

    def setEndOfMibError(self, pdu, errorIndex):
        self.setErrorStatus(pdu, 2)

    def setNoSuchInstanceError(self, pdu, errorIndex):
        self.setEndOfMibError(pdu, errorIndex)
    
    def getVarBindList(self, pdu):
        return pdu.getComponentByPosition(3)
    def setVarBindList(self, pdu, varBindList):
        varBindList = pdu.setComponentByPosition(3, varBindList)

    def getVarBinds(self, pdu):
        return map(lambda x: apiVarBind.getOIDVal(x),
                   pdu.getComponentByPosition(3))
    def setVarBinds(self, pdu, varBinds):
        varBindList = pdu.setComponentByPosition(3).getComponentByPosition(3)
        varBindList.clear()
        idx = 0
        for varBind in varBinds:
            if type(varBind) is types.InstanceType:
                varBindList.setComponentByPosition(idx, varBind)
            else:
                varBindList.setComponentByPosition(idx)
                apiVarBind.setOIDVal(
                    varBindList.getComponentByPosition(idx), varBind
                    )
            idx = idx + 1

    def getResponse(self, reqPDU):
        rspPDU = GetResponsePDU()
        self.setDefaults(rspPDU)
        self.setRequestID(rspPDU, self.getRequestID(reqPDU))
        return rspPDU

    def getVarBindTable(self, reqPDU, rspPDU):
        if apiPDU.getErrorStatus(rspPDU) == 2:
            return [ map(lambda (x,y): (x, None), apiPDU.getVarBinds(reqPDU)) ]
        else:
            return [ apiPDU.getVarBinds(rspPDU) ]

apiPDU = PDUAPI()

class TrapPDUAPI:
    try:
        import socket
        agentAddress = IpAddress(socket.gethostbyname(socket.gethostname()))
    except:
        agentAddress = IpAddress('0.0.0.0')
    def setDefaults(self, pdu):
        pdu.setComponentByPosition(0, (1,3,6,1,4,1,20408))
        pdu.setComponentByPosition(1).getComponentByPosition(1).setComponentByPosition(0, self.agentAddress)
        pdu.setComponentByPosition(2, 0)
        pdu.setComponentByPosition(3, 0)
        pdu.setComponentByPosition(4, 0)
        pdu.setComponentByPosition(5)

    def getEnterprise(self, pdu): return pdu.getComponentByPosition(0)
    def setEnterprise(self, pdu, value): pdu.setComponentByPosition(0, value)

    def getAgentAddr(self, pdu):
        return pdu.getComponentByPosition(1).getComponentByPosition(0)
    def setAgentAddr(self, pdu, value):
        pdu.getComponentByPosition(1).setComponentByPosition(0, value)

    def getGenericTrap(self, pdu): return pdu.getComponentByPosition(2)
    def setGenericTrap(self, pdu, value): pdu.setComponentByPosition(2, value)

    def getSpecificTrap(self, pdu): return pdu.getComponentByPosition(3)
    def setSpecificTrap(self, pdu, value): pdu.setComponentByPosition(3, value)

    def getTimeStamp(self, pdu): return pdu.getComponentByPosition(4)
    def setTimeStamp(self, pdu, value): pdu.setComponentByPosition(4, value)

    def getVarBindList(self, pdu):
        return pdu.getComponentByPosition(5)
    def setVarBindList(self, pdu, varBindList):
        varBindList = pdu.setComponentByPosition(5, varBindList)

    def getVarBinds(self, pdu):
        return map(lambda x: apiVarBind.getOIDVal(x),
                   pdu.getComponentByPosition(5))
    def setVarBinds(self, pdu, varBinds):
        varBindList = pdu.setComponentByPosition(5).getComponentByPosition(5)
        varBindList.clear()
        idx = 0
        for varBind in varBinds:
            if type(varBind) is types.InstanceType:
                varBindList.setComponentByPosition(idx, varBind)
            else:
                varBindList.setComponentByPosition(idx)
                apiVarBind.setOIDVal(
                    varBindList.getComponentByPosition(idx), varBind
                    )
            idx = idx + 1

apiTrapPDU = TrapPDUAPI()

class MessageAPI:
    def setDefaults(self, msg):
        msg.setComponentByPosition(0, 0)
        msg.setComponentByPosition(1, 'public')
        return msg

    def getVersion(self, msg): return msg.getComponentByPosition(0)
    def setVersion(self, msg, value): msg.setComponentByPosition(0, value)

    def getCommunity(self, msg): return msg.getComponentByPosition(1)
    def setCommunity(self, msg, value): msg.setComponentByPosition(1, value)
        
    def getPDU(self, msg): return msg.getComponentByPosition(2).getComponent()
    def setPDU(self, msg, value):
        msg.setComponentByPosition(2).getComponentByPosition(2).setComponentByType(value.getTagSet(), value, 1)

    def getResponse(self, reqMsg):
        rspMsg = Message()
        self.setDefaults(rspMsg)
        self.setVersion(rspMsg, self.getVersion(reqMsg))
        self.setCommunity(rspMsg, self.getCommunity(reqMsg))
        self.setPDU(rspMsg, apiPDU.getResponse(self.getPDU(reqMsg)))
        return rspMsg

apiMessage = MessageAPI()

