import socket, string, types
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen, mibvar
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import view
from pysnmp import error
from pyasn1.type import univ

# Auth protocol
usmHMACMD5AuthProtocol = config.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = config.usmHMACSHAAuthProtocol
usmNoAuthProtocol = config.usmNoAuthProtocol

# Privacy protocol
usmDESPrivProtocol = config.usmDESPrivProtocol
usmNoPrivProtocol = config.usmNoPrivProtocol

class CommunityData:
    mpModel=1 # Default is SMIv2
    securityModel=mpModel+1
    securityLevel='noAuthNoPriv'
    def __init__(self, securityName, communityName, mpModel=None):
        self.securityName = securityName
        self.communityName = communityName
        if mpModel is not None:
            self.mpModel = mpModel
            self.securityModel = mpModel + 1

class UsmUserData:
    authKey = privKey = ''
    securityLevel='noAuthNoPriv'
    securityModel=3
    mpModel=2
    def __init__(self, securityName,
                 authKey='', privKey='',
                 authProtocol=usmNoAuthProtocol,
                 privProtocol=usmNoPrivProtocol):
        self.securityName = securityName
        if authKey:
            self.authKey = authKey
            if authProtocol == usmNoAuthProtocol:
                self.authProtocol = usmHMACMD5AuthProtocol
            else:
                self.authProtocol = authProtocol
            if self.securityLevel != 'authPriv':
                self.securityLevel = 'authNoPriv'
        else:
            self.authProtocol = usmNoAuthProtocol
            self.privProtocol = usmNoPrivProtocol
        if privKey:
            self.privKey = privKey
            if self.authProtocol == usmNoAuthProtocol:
                raise error.PySnmpError('Privacy implies authenticity')
            self.securityLevel = 'authPriv'
            if privProtocol == usmNoPrivProtocol:
                self.privProtocol = usmDESPrivProtocol
            else:
                self.privProtocol = privProtocol
        else:
            self.privProtocol = usmNoPrivProtocol
            
class UdpTransportTarget:
    transportDomain = udp.domainName
    transport = udp.UdpSocketTransport().openClientMode()
    retries = timeout = None  # XXX
    def __init__(self, transportAddr):
        self.transportAddr = (
            socket.gethostbyname(transportAddr[0]), transportAddr[1]
            )

class AsynCommandGenerator:
    _null = univ.Null()
    def __init__(self, snmpEngine=None):
        if snmpEngine is None:
            self.snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine
        self.mibViewController = view.MibViewController(
            self.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
            )
        self.__knownAuths = {}
        self.__knownTransports = {}
        self.__knownTransportAddrs = {}

    def _configure(self, authData, transportTarget, tagList=''):
        paramsName = '%s-params' % (authData.securityName,)
        if not self.__knownAuths.has_key(authData):
            if isinstance(authData, CommunityData):
                config.addV1System(
                    self.snmpEngine,
                    authData.securityName,
                    authData.communityName
                    )
                config.addTargetParams(
                    self.snmpEngine, paramsName,
                    authData.securityName, authData.securityLevel,
                    authData.mpModel
                    )
            elif isinstance(authData, UsmUserData):
                config.addV3User(
                    self.snmpEngine,
                    authData.securityName,
                    authData.authProtocol, authData.authKey,
                    authData.privProtocol, authData.privKey
                    )
                config.addTargetParams(
                    self.snmpEngine, paramsName,
                    authData.securityName, authData.securityLevel
                    )
            else:
                raise error.PySnmpError('Unsupported SNMP version')
            self.__knownAuths[authData] = 1

        if not self.__knownTransports.has_key(transportTarget.transport):
            config.addSocketTransport(
                self.snmpEngine,
                transportTarget.transportDomain,
                transportTarget.transport
                )
            self.__knownTransports[transportTarget.transport] = 1
            
        addrName = str(transportTarget.transportAddr)
        if not self.__knownTransportAddrs.has_key(addrName):
            config.addTargetAddr(
                self.snmpEngine, addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName,
                tagList=tagList
                )
            self.__knownTransportAddrs[addrName] = 1
            
        return addrName, paramsName

    # Async SNMP apps
    
    def asyncGetCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName, paramsName = self._configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            varBinds.append((name + oid, self._null))
        return cmdgen.GetCommandGenerator().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx
            )

    def asyncSetCmd(
        self, authData, transportTarget, varBinds, (cbFun, cbCtx)
        ):
        addrName, paramsName = self._configure(
            authData, transportTarget
            )
        __varBinds = []
        for varName, varVal in varBinds:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            __varBinds.append((name + oid, varVal))
        return cmdgen.SetCommandGenerator().sendReq(
            self.snmpEngine, addrName, __varBinds, cbFun, cbCtx
            )
        
    def asyncNextCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName, paramsName = self._configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            varBinds.append((name + oid, self._null))
        return cmdgen.NextCommandGenerator().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx
            )

    def asyncBulkCmd(
        self, authData, transportTarget, nonRepeaters, maxRepetitions,
        varNames, (cbFun, cbCtx)
        ):
        addrName, paramsName = self._configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            varBinds.append((name + oid, self._null))
        return cmdgen.BulkCommandGenerator().sendReq(
            self.snmpEngine, addrName, nonRepeaters, maxRepetitions,
            varBinds, cbFun, cbCtx
            )

class CommandGenerator(AsynCommandGenerator):
    def getCmd(self, authData, transportTarget, *varNames):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBinds, appReturn
            ):
            appReturn['errorIndication'] = errorIndication
            appReturn['errorStatus'] = errorStatus
            appReturn['errorIndex'] = errorIndex
            appReturn['varBinds'] = varBinds

        appReturn = {}
        self.asyncGetCmd(
            authData, transportTarget, varNames, (__cbFun, appReturn)
            )
        self.snmpEngine.transportDispatcher.runDispatcher()
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds']
            )

    def setCmd(self, authData, transportTarget, *varBinds):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBinds, appReturn
            ):
            appReturn['errorIndication'] = errorIndication
            appReturn['errorStatus'] = errorStatus
            appReturn['errorIndex'] = errorIndex
            appReturn['varBinds'] = varBinds

        appReturn = {}
        self.asyncSetCmd(
            authData, transportTarget, varBinds, (__cbFun, appReturn)
            )
        self.snmpEngine.transportDispatcher.runDispatcher()
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds']
            )

    def nextCmd(self, authData, transportTarget, *varNames):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBindTable, (varBindHead, varBindTotalTable, appReturn)
            ):
            if errorIndication or errorStatus:
                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBindTable'] = varBindTable
                return
            else:
                varBindTableRow = varBindTable[-1]
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    if head[idx].isPrefixOf(name):  # XXX causes extra rows
                        break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                varBindTotalTable.extend(varBindTable)

            return 1 # continue table retrieval
        
        head = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.mibNameToOid(self.mibViewController, x), varNames))

        appReturn = {}
        self.asyncNextCmd(
            authData, transportTarget, varNames, (__cbFun, (head,[],appReturn))
            )

        self.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
            )

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, *varNames):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBindTable, (varBindHead, varBindTotalTable, appReturn)
            ):
            if errorIndication or errorStatus:
                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBindTable'] = varBindTable
                return
            else:
                varBindTotalTable.extend(varBindTable) # XXX out of table 
                                                       # rows possible
                varBindTableRow = varBindTable[-1]
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    if head[idx].isPrefixOf(name):
                        break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                
            return 1 # continue table retrieval
        
        head = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.mibNameToOid(self.mibViewController, x), varNames))

        appReturn = {}
        
        self.asyncBulkCmd(
            authData, transportTarget, nonRepeaters, maxRepetitions,
            varNames, (__cbFun, (head, [], appReturn))
            )

        self.snmpEngine.transportDispatcher.runDispatcher()
        
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
            )
