import socket, sys
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen, mibvar
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.proto import errind
from pysnmp.smi import view
from pysnmp import nextid, error
from pyasn1.type import univ, base
from pyasn1.compat.octets import null

# Auth protocol
usmHMACMD5AuthProtocol = config.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = config.usmHMACSHAAuthProtocol
usmNoAuthProtocol = config.usmNoAuthProtocol

# Privacy protocol
usmDESPrivProtocol = config.usmDESPrivProtocol
usm3DESEDEPrivProtocol = config.usm3DESEDEPrivProtocol
usmAesCfb128Protocol = config.usmAesCfb128Protocol
usmAesCfb192Protocol = config.usmAesCfb192Protocol
usmAesCfb256Protocol = config.usmAesCfb256Protocol
usmNoPrivProtocol = config.usmNoPrivProtocol

nextID = nextid.Integer(0xffffffff)

class CommunityData:
    mpModel = 1 # Default is SMIv2
    securityModel = mpModel + 1
    securityLevel = 'noAuthNoPriv'
    contextName = null
    def __init__(self, securityName, communityName=None, mpModel=None,
                 contextEngineId=None, contextName=None):
        self.securityName = securityName
        self.communityName = communityName
        if mpModel is not None:
            self.mpModel = mpModel
            self.securityModel = mpModel + 1
        self.contextEngineId = contextEngineId
        if contextName is not None:
            self.contextName = contextName
        # Autogenerate securityName if not specified
        if communityName is None:
            self.communityName = securityName
            self.securityName = 's%s' % hash(
                ( securityName, self.mpModel,
                  self.contextEngineId, self.contextName )
                )
            
    def __repr__(self):
        return '%s("%s", <COMMUNITY>, %r, %r, %r)' % (
            self.__class__.__name__,
            self.securityName,
            self.mpModel,
            self.contextEngineId,
            self.contextName
            )

    def __hash__(self): return hash(self.securityName)

    def __eq__(self, other): return self.securityName == other
    def __ne__(self, other): return self.securityName != other
    def __lt__(self, other): return self.securityName < other
    def __le__(self, other): return self.securityName <= other
    def __gt__(self, other): return self.securityName > other
    def __ge__(self, other): return self.securityName >= other

class UsmUserData:
    authKey = privKey = None
    authProtocol = usmNoAuthProtocol
    privProtocol = usmNoPrivProtocol
    securityLevel = 'noAuthNoPriv'
    securityModel = 3
    mpModel = 3
    contextName = null
    def __init__(self, securityName,
                 authKey=None, privKey=None,
                 authProtocol=None, privProtocol=None,
                 contextEngineId=None, contextName=None):
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

        self.contextEngineId = contextEngineId
        if contextName is not None:
            self.contextName = contextName
        
    def __repr__(self):
        return '%s("%s", <AUTHKEY>, <PRIVKEY>, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.securityName,
            self.authProtocol,
            self.privProtocol,
            self.contextEngineId,
            self.contextName
            )

    def __hash__(self): return hash(self.securityName)

    def __eq__(self, other): return self.securityName == other
    def __ne__(self, other): return self.securityName != other
    def __lt__(self, other): return self.securityName < other
    def __le__(self, other): return self.securityName <= other
    def __gt__(self, other): return self.securityName > other
    def __ge__(self, other): return self.securityName >= other
    
class UdpTransportTarget:
    transportDomain = udp.domainName
    def __init__(self, transportAddr, timeout=1, retries=5):
        self.transportAddr = (
            socket.gethostbyname(transportAddr[0]), transportAddr[1]
            )
        self.timeout = timeout
        self.retries = retries

    def __repr__(self): return '%s(%r, %r, %r)' % (
        self.__class__.__name__, self.transportAddr, self.timeout, self.retries
        )

    def __hash__(self): return hash(self.transportAddr)
    
    def __eq__(self, other): return self.transportAddr == other
    def __ne__(self, other): return self.transportAddr != other
    def __lt__(self, other): return self.transportAddr < other
    def __le__(self, other): return self.transportAddr <= other
    def __gt__(self, other): return self.transportAddr > other
    def __ge__(self, other): return self.transportAddr >= other
    
    def openClientMode(self):
        self.transport = udp.UdpSocketTransport().openClientMode()
        return self.transport
        
class AsynCommandGenerator:
    _null = univ.Null('')
    def __init__(self, snmpEngine=None):
        self.__knownAuths = {}
        self.__knownParams = {}
        self.__knownTransports = {}
        self.__knownTransportAddrs = {}
        if snmpEngine is None:
            self.snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine
        self.mibViewController = view.MibViewController(
            self.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
            )

    def __del__(self): self.uncfgCmdGen()

    def cfgCmdGen(self, authData, transportTarget, tagList=null):
        if authData not in self.__knownAuths:
            if isinstance(authData, CommunityData):
                config.addV1System(
                    self.snmpEngine,
                    authData.securityName,
                    authData.communityName,
                    authData.contextEngineId,
                    authData.contextName,
                    tagList
                    )
            elif isinstance(authData, UsmUserData):
                config.addV3User(
                    self.snmpEngine,
                    authData.securityName,
                    authData.authProtocol, authData.authKey,
                    authData.privProtocol, authData.privKey,
                    authData.contextEngineId
                    )
            else:
                raise error.PySnmpError('Unsupported authentication object')

            self.__knownAuths[authData] = 1

        k = authData.securityName, authData.securityLevel, authData.mpModel
        if k in self.__knownParams:
            paramsName = self.__knownParams[k]
        else:
            paramsName = 'p%s' % nextID()
            config.addTargetParams(
                self.snmpEngine, paramsName,
                authData.securityName, authData.securityLevel, authData.mpModel
                )
            self.__knownParams[k] = paramsName

        if transportTarget.transportDomain not in self.__knownTransports:
            transport = transportTarget.openClientMode()
            config.addSocketTransport(
                self.snmpEngine,
                transportTarget.transportDomain,
                transport
                )
            self.__knownTransports[transportTarget.transportDomain] = transport

        k = paramsName, transportTarget, tagList
        if k in self.__knownTransportAddrs:
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
        for authData in self.__knownAuths:
            if isinstance(authData, CommunityData):
                config.delV1System(
                    self.snmpEngine,
                    authData.securityName
                    )
            elif isinstance(authData, UsmUserData):
                config.delV3User(
                    self.snmpEngine, authData.securityName
                    )
            else:
                raise error.PySnmpError('Unsupported authentication object')
        self.__knownAuths.clear()

        for paramsName in self.__knownParams.values():
            config.delTargetParams(
                self.snmpEngine, paramsName
                )
        self.__knownParams.clear()
        
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
                
    if sys.version_info[0] <= 2:
        intTypes = (int, long)
    else:
        intTypes = (int,)

    def makeReadVarBinds(self, varNames):
        varBinds = []
        for varName in varNames:
            if isinstance(varName[0], self.intTypes):
                name = varName
            else:
                name, oid = mibvar.mibNameToOid(
                    self.mibViewController, varName
                    )
                name = name + oid
            varBinds.append((name, self._null))
        return varBinds

    # Async SNMP apps

    def getCmd(self, authData, transportTarget, varNames, cbInfo):
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
            )
        varBinds = self.makeReadVarBinds(varNames)
        return cmdgen.GetCommandGenerator().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx,
            authData.contextEngineId, authData.contextName
            )
    
    asyncGetCmd = getCmd
    
    def setCmd(self, authData, transportTarget, varBinds, cbInfo):
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
            )
        __varBinds = []
        for varName, varVal in varBinds:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, varName
                )
            if not isinstance(varVal, base.AbstractSimpleAsn1Item):
                ((symName, modName), suffix) = mibvar.oidToMibName(
                    self.mibViewController, name + oid
                    )
                syntax = mibvar.cloneFromMibValue(
                    self.mibViewController, modName, symName, varVal
                    )
                if syntax is None:
                    raise error.PySnmpError(
                        'Value type MIB lookup failed for %r' % (varName,)
                        )
                varVal = syntax.clone(varVal)
            __varBinds.append((name + oid, varVal))
        return cmdgen.SetCommandGenerator().sendReq(
            self.snmpEngine, addrName, __varBinds, cbFun, cbCtx,
            authData.contextEngineId, authData.contextName
            )
    
    asyncSetCmd = setCmd
    
    def nextCmd(self, authData, transportTarget, varNames, cbInfo):
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
            )
        varBinds = self.makeReadVarBinds(varNames)
        return cmdgen.NextCommandGenerator().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx,
            authData.contextEngineId, authData.contextName
            )

    asyncNextCmd = nextCmd
    
    def bulkCmd(self, authData, transportTarget, nonRepeaters, maxRepetitions,
                varNames, cbInfo):
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
            )
        varBinds = self.makeReadVarBinds(varNames)
        return cmdgen.BulkCommandGenerator().sendReq(
            self.snmpEngine, addrName,
            nonRepeaters, maxRepetitions, varBinds, cbFun, cbCtx,
            authData.contextEngineId, authData.contextName
            )

    asyncBulkCmd = bulkCmd

class CommandGenerator:
    lexicographicMode = ignoreNonIncreasingOid = maxRows = None
    def __init__(self, snmpEngine=None, asynCmdGen=None):
        if asynCmdGen is None:
            self.__asynCmdGen = AsynCommandGenerator(snmpEngine)
        else:
            self.__asynCmdGen = asynCmdGen

        # compatibility attributes
        self.snmpEngine = self.__asynCmdGen.snmpEngine
        self.mibViewController = self.__asynCmdGen.mibViewController
        
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
        self.__asynCmdGen.getCmd(
            authData, transportTarget, varNames, (__cbFun, appReturn)
            )
        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()
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
        self.__asynCmdGen.setCmd(
            authData, transportTarget, varBinds, (__cbFun, appReturn)
            )
        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds']
            )

    def nextCmd(self, authData, transportTarget, *varNames):
        def __cbFun(sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBindTable, cbCtx):
            (self, varBindHead, varBindTotalTable, appReturn) = cbCtx
            if self.ignoreNonIncreasingOid and errorIndication and \
               isinstance(errorIndication, errind.OidNotIncreasing):
                errorIndication = None
            if errorStatus or errorIndication:
                appReturn['errorIndication'] = errorIndication
                if errorStatus == 2:
                    # Hide SNMPv1 noSuchName error which leaks in here
                    # from SNMPv1 Agent through internal pysnmp proxy.
                    appReturn['errorStatus'] = errorStatus.clone(0)
                    appReturn['errorIndex'] = errorIndex.clone(0)
                else:
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                appReturn['varBindTable'] = varBindTotalTable
                return
            else:
                if self.maxRows and len(varBindTotalTable) >= self.maxRows:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable[:self.maxRows]
                    return
                
                varBindTableRow = varBindTable and varBindTable[-1] or varBindTable
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    # XXX extra rows
                    if not isinstance(val, univ.Null):
                        if self.lexicographicMode:
                            if varBindHead[idx] <= name:
                                break
                        else:
                            if varBindHead[idx].isPrefixOf(name):
                                break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                
                varBindTotalTable.extend(varBindTable)

                return 1 # continue table retrieval

        varBindHead = []
        for varName in varNames:
            name, suffix = mibvar.mibNameToOid(
                self.__asynCmdGen.mibViewController, varName
                )
            varBindHead.append(univ.ObjectIdentifier(name + suffix))

        appReturn = {}
        self.__asynCmdGen.nextCmd(
            authData, transportTarget, varNames,
            (__cbFun, (self, varBindHead, [], appReturn))
            )

        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
            )

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, *varNames):
        def __cbFun(sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBindTable, cbCtx):
            (self, varBindHead, varBindTotalTable, appReturn) = cbCtx
            if self.ignoreNonIncreasingOid and errorIndication and \
               isinstance(errorIndication, errind.OidNotIncreasing):
                errorIndication = None
            if errorStatus or errorIndication:
                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBindTable'] = varBindTable
                return
            else:
                while varBindTable:
                    if len(varBindTable[-1]) != len(varBindHead):
                        # Fix possibly non-rectangular table
                        del varBindTable[-1]
                    else:
                        break

                varBindTotalTable.extend(varBindTable) # XXX out of table 
                                                       # rows possible

                if self.maxRows and len(varBindTotalTable) >= self.maxRows:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable[:self.maxRows]
                    return

                varBindTableRow = varBindTable and varBindTable[-1] or varBindTable
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    if not isinstance(val, univ.Null):
                        if self.lexicographicMode:
                            if varBindHead[idx] <= name:
                                break
                        else:
                            if varBindHead[idx].isPrefixOf(name):
                                break
                else:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    appReturn['varBindTable'] = varBindTotalTable
                    return

                return 1 # continue table retrieval

        varBindHead = []
        for varName in varNames:
            name, suffix = mibvar.mibNameToOid(
                self.__asynCmdGen.mibViewController, varName
                )
            varBindHead.append(univ.ObjectIdentifier(name + suffix))

        appReturn = {}
        
        self.__asynCmdGen.bulkCmd(
            authData, transportTarget, nonRepeaters, maxRepetitions,
            varNames, (__cbFun, (self, varBindHead, [], appReturn))
            )

        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()
        
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
            )
