import socket, string, types
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen, mibvar
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import view
from pysnmp import nextid, error
from pyasn1.type import univ

# Auth protocol
usmHMACMD5AuthProtocol = config.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = config.usmHMACSHAAuthProtocol
usmNoAuthProtocol = config.usmNoAuthProtocol

# Privacy protocol
usmDESPrivProtocol = config.usmDESPrivProtocol
usmAesCfb128Protocol = config.usmAesCfb128Protocol
usmNoPrivProtocol = config.usmNoPrivProtocol

nextID = nextid.Integer(0xffffffffL)

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
        self.__cmp = self.mpModel, self.securityModel, self.securityLevel, self.securityName, self.communityName
        self.__hash = hash(self.__cmp)
            
    def __repr__(self): return '%s("%s", <COMMUNITY>, %s)' % (
        self.__class__.__name__,
        self.securityName,
        self.mpModel
        )

    def __hash__(self): return self.__hash
    def __cmp__(self, other): return cmp(self.__cmp, other)

class UsmUserData:
    authKey = privKey = None
    authProtocol = usmNoAuthProtocol
    privProtocol = usmNoPrivProtocol
    securityLevel='noAuthNoPriv'
    securityModel=3
    mpModel=2
    def __init__(self, securityName,
                 authKey=None, privKey=None,
                 authProtocol=None, privProtocol=None):
        self.securityName = securityName
        
        if authKey is not None:
            self.authKey = authKey
            if authProtocol is None:
                self.authProtocol = usmHMACMD5AuthProtocol
            else:
                self.authProtocol = authProtocol
            if self.securityLevel != 'authPriv':
                self.securityLevel = 'authNoPriv'

        if privKey is not None:
            self.privKey = privKey
            if self.authProtocol == usmNoAuthProtocol:
                raise error.PySnmpError('Privacy implies authenticity')
            self.securityLevel = 'authPriv'
            if privProtocol is None:
                self.privProtocol = usmDESPrivProtocol
            else:
                self.privProtocol = privProtocol

        self.__cmp = self.mpModel, self.securityModel, self.securityLevel, self.securityName, self.authProtocol, self.authKey, self.privProtocol, self.privKey
        self.__hash = hash(self.__cmp)

    def __repr__(self): return '%s("%s", <AUTHKEY>, <PRIVKEY>, %s, %s)' % (
        self.__class__.__name__,
        self.securityName,
        self.authProtocol,
        self.privProtocol
        )

    def __hash__(self): return self.__hash
    def __cmp__(self, other): return cmp(self.__cmp, other)
    
class UdpTransportTarget:
    transportDomain = udp.domainName
    def __init__(self, transportAddr, timeout=1, retries=5):
        self.transportAddr = (
            socket.gethostbyname(transportAddr[0]), transportAddr[1]
            )
        self.timeout = timeout
        self.retries = retries

    def __repr__(self): return '%s(("%s", %s), %s, %s)' % (
        self.__class__.__name__,
        self.transportAddr[0], self.transportAddr[1],
        self.timeout, self.retries
        )

    def __hash__(self): return hash(self.transportAddr)
    def __cmp__(self, other): return cmp(self.transportAddr, other)
    
    def openClientMode(self):
        self.transport = udp.UdpSocketTransport().openClientMode()
        return self.transport
        
class AsynCommandGenerator:
    _null = univ.Null('')
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

    def __del__(self): self.uncfgCmdGen()

    def cfgCmdGen(self, authData, transportTarget, tagList=''):
        if self.__knownAuths.has_key(authData):
            paramsName = self.__knownAuths[authData]
        else:
            paramsName = 'p%s' % nextID()
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
            self.__knownAuths[authData] = paramsName

        if not self.__knownTransports.has_key(transportTarget.transportDomain):
            transport = transportTarget.openClientMode()
            config.addSocketTransport(
                self.snmpEngine,
                transportTarget.transportDomain,
                transport
                )
            self.__knownTransports[transportTarget.transportDomain] = transport

        k = transportTarget, tagList
        if self.__knownTransportAddrs.has_key(k):
            addrName = self.__knownTransportAddrs[k]
        else:
            addrName = 'a%s' % nextID()
            config.addTargetAddr(
                self.snmpEngine, addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName,
                transportTarget.timeout * 100,
                transportTarget.retries,
                tagList                
                )
            self.__knownTransportAddrs[k] = addrName

        return addrName, paramsName

    def uncfgCmdGen(self):
        for authData, paramsName in self.__knownAuths.items():
            if isinstance(authData, CommunityData):
                config.delV1System(
                    self.snmpEngine,
                    authData.securityName
                    )
                config.delTargetParams(
                    self.snmpEngine, paramsName
                    )
            elif isinstance(authData, UsmUserData):
                config.delV3User(
                    self.snmpEngine, authData.securityName
                    )
                config.delTargetParams(
                    self.snmpEngine, paramsName
                    )
            else:
                raise error.PySnmpError('Unsupported SNMP version')
        self.__knownAuths.clear()

        for transportDomain, transport in self.__knownTransports.items():
            config.delSocketTransport(
                self.snmpEngine, transportDomain
                )
            transport.closeTransport()
        self.__knownTransports.clear()

        for addrName in self.__knownTransportAddrs.values():
            config.delTargetAddr(
                self.snmpEngine, addrName
                )
        self.__knownTransportAddrs.clear()
                
    # Async SNMP apps
    
    def asyncGetCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName, paramsName = self.cfgCmdGen(
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
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
            )
        __varBinds = []
        for varName, varVal in varBinds:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            if not type(varVal) == types.InstanceType:
                ((symName, modName), suffix) = mibvar.oidToMibName(
                    self.mibViewController, name + oid
                    )
                syntax = mibvar.cloneFromMibValue(
                    self.mibViewController, modName, symName, varVal
                    )
                if syntax is None:
                    raise error.PySnmpError(
                        'Value type MIB lookup failed for %s' % repr(varName)
                        )
                varVal = syntax.clone(varVal)
            __varBinds.append((name + oid, varVal))
        return cmdgen.SetCommandGenerator().sendReq(
            self.snmpEngine, addrName, __varBinds, cbFun, cbCtx
            )
        
    def asyncNextCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName, paramsName = self.cfgCmdGen(
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
        addrName, paramsName = self.cfgCmdGen(
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
                    # XXX extra rows
                    if val is not None and varBindHead[idx].isPrefixOf(name):
                        break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                varBindTotalTable.extend(varBindTable)

            return 1 # continue table retrieval
        
        varBindHead = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.mibNameToOid(self.mibViewController, x), varNames))

        appReturn = {}
        self.asyncNextCmd(
            authData, transportTarget, varNames,
            (__cbFun, (varBindHead,[],appReturn))
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
                    if val is not None and varBindHead[idx].isPrefixOf(name):
                        break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                
            return 1 # continue table retrieval
        
        varBindHead = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.mibNameToOid(self.mibViewController, x), varNames))

        appReturn = {}
        
        self.asyncBulkCmd(
            authData, transportTarget, nonRepeaters, maxRepetitions,
            varNames, (__cbFun, (varBindHead, [], appReturn))
            )

        self.snmpEngine.transportDispatcher.runDispatcher()
        
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
            )
