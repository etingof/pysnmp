from pyasn1.type import univ
from pysnmp.proto import rfc1155, rfc1157, error
from pysnmp import nextid

# Shortcuts to SNMP types
Integer = univ.Integer
OctetString = univ.OctetString
Null = univ.Null
null = Null('')
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
    def setOIDVal(self, varBind, oidVal):
        (oid, val) = oidVal
        varBind.setComponentByPosition(0, oid)
        if val is None: val = null
        varBind.setComponentByPosition(1).getComponentByPosition(1).setComponentByType(val.getTagSet(), val, 1, verifyConstraints=False)
        return varBind
    
    def getOIDVal(self, varBind):
        return varBind[0], varBind[1].getComponent(1)

apiVarBind = VarBindAPI()

getNextRequestID = nextid.Integer(0xffffff)

class PDUAPI:
    _errorStatus = rfc1157._errorStatus.clone(0)
    _errorIndex = Integer(0)
    def setDefaults(self, pdu):
        pdu.setComponentByPosition(
            0, getNextRequestID(), verifyConstraints=False
            )
        pdu.setComponentByPosition(
            1, self._errorStatus, verifyConstraints=False
            )
        pdu.setComponentByPosition(
            2, self._errorIndex, verifyConstraints=False
            )
        pdu.setComponentByPosition(3)
        
    def getRequestID(self, pdu): return pdu.getComponentByPosition(0)
    def setRequestID(self, pdu, value): pdu.setComponentByPosition(0, value)

    def getErrorStatus(self, pdu): return pdu.getComponentByPosition(1)
    def setErrorStatus(self, pdu, value): pdu.setComponentByPosition(1, value)

    def getErrorIndex(self, pdu, muteErrors=False):
        errorIndex = pdu.getComponentByPosition(2)
        if errorIndex > len(pdu[3]):
            if muteErrors:
                return errorIndex.clone(len(pdu[3]))
            raise error.ProtocolError(
                'Error index out of range: %s > %s' % (errorIndex, len(pdu[3]))
                )
        return errorIndex
    def setErrorIndex(self, pdu, value):
        pdu.setComponentByPosition(2, value)

    def setEndOfMibError(self, pdu, errorIndex):
        self.setErrorIndex(pdu, errorIndex)
        self.setErrorStatus(pdu, 2)

    def setNoSuchInstanceError(self, pdu, errorIndex):
        self.setEndOfMibError(pdu, errorIndex)
    
    def getVarBindList(self, pdu):
        return pdu.getComponentByPosition(3)

    def setVarBindList(self, pdu, varBindList):
        varBindList = pdu.setComponentByPosition(3, varBindList)
    def getVarBinds(self, pdu):
        varBinds = []
        for varBind in pdu.getComponentByPosition(3):
            varBinds.append(apiVarBind.getOIDVal(varBind))
        return varBinds
    def setVarBinds(self, pdu, varBinds):
        varBindList = pdu.setComponentByPosition(3).getComponentByPosition(3)
        varBindList.clear()
        idx = 0
        for varBind in varBinds:
            if isinstance(varBind, VarBind):
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
            varBindRow = []
            for varBind in apiPDU.getVarBinds(reqPDU):
                varBindRow.append((varBind[0], null))
            return [ varBindRow ]
        else:
            return [ apiPDU.getVarBinds(rspPDU) ]

apiPDU = PDUAPI()

class TrapPDUAPI:
    _networkAddress = None
    _entOid = ObjectIdentifier((1,3,6,1,4,1,20408))
    _genericTrap = rfc1157._genericTrap.clone('coldStart')
    _zeroInt = univ.Integer(0)
    _zeroTime = TimeTicks(0)
    def setDefaults(self, pdu):
        if self._networkAddress is None:
            try:
                import socket
                agentAddress = IpAddress(socket.gethostbyname(socket.gethostname()))
            except:
                agentAddress = IpAddress('0.0.0.0')
        self._networkAddress = NetworkAddress().setComponentByPosition(0, agentAddress)
        pdu.setComponentByPosition(0, self._entOid, verifyConstraints=False)
        pdu.setComponentByPosition(1, self._networkAddress, verifyConstraints=False)
        pdu.setComponentByPosition(2, self._genericTrap,verifyConstraints=False)
        pdu.setComponentByPosition(3, self._zeroInt, verifyConstraints=False)
        pdu.setComponentByPosition(4, self._zeroTime, verifyConstraints=False)
        pdu.setComponentByPosition(5)

    def getEnterprise(self, pdu): return pdu.getComponentByPosition(0)
    def setEnterprise(self, pdu, value): pdu.setComponentByPosition(0, value)

    def getAgentAddr(self, pdu):
        return pdu.getComponentByPosition(1).getComponentByPosition(0)
    def setAgentAddr(self, pdu, value):
        pdu.setComponentByPosition(1).getComponentByPosition(1).setComponentByPosition(0, value)

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
        varBinds = []
        for varBind in pdu.getComponentByPosition(5):
            varBinds.append(apiVarBind.getOIDVal(varBind))
        return varBinds
    def setVarBinds(self, pdu, varBinds):
        varBindList = pdu.setComponentByPosition(5).getComponentByPosition(5)
        varBindList.clear()
        idx = 0
        for varBind in varBinds:
            if isinstance(varBind, VarBind):
                varBindList.setComponentByPosition(idx, varBind)
            else:
                varBindList.setComponentByPosition(idx)
                apiVarBind.setOIDVal(
                    varBindList.getComponentByPosition(idx), varBind
                    )
            idx = idx + 1

apiTrapPDU = TrapPDUAPI()

class MessageAPI:
    _version = rfc1157._version.clone(0)
    _community = univ.OctetString('public')
    def setDefaults(self, msg):
        msg.setComponentByPosition(0, self._version, verifyConstraints=False)
        msg.setComponentByPosition(1, self._community, verifyConstraints=False)
        return msg

    def getVersion(self, msg): return msg.getComponentByPosition(0)
    def setVersion(self, msg, value): msg.setComponentByPosition(0, value)

    def getCommunity(self, msg): return msg.getComponentByPosition(1)
    def setCommunity(self, msg, value): msg.setComponentByPosition(1, value)
        
    def getPDU(self, msg): return msg.getComponentByPosition(2).getComponent()
    def setPDU(self, msg, value):
        msg.setComponentByPosition(2).getComponentByPosition(2).setComponentByType(value.getTagSet(), value, 1, verifyConstraints=False)

    def getResponse(self, reqMsg):
        rspMsg = Message()
        self.setDefaults(rspMsg)
        self.setVersion(rspMsg, self.getVersion(reqMsg))
        self.setCommunity(rspMsg, self.getCommunity(reqMsg))
        self.setPDU(rspMsg, apiPDU.getResponse(self.getPDU(reqMsg)))
        return rspMsg

apiMessage = MessageAPI()

