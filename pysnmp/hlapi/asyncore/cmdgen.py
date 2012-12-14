from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.entity.rfc3413.oneliner.mibvar import MibVariable
from pysnmp.entity.rfc3413.oneliner.auth import CommunityData, UsmUserData
from pysnmp.entity.rfc3413.oneliner.target import UdpTransportTarget, \
    Udp6TransportTarget, UnixTransportTarget 
from pysnmp.proto import rfc1905, errind
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

    def cfgCmdGen(self, authData, transportTarget):
        if authData.securityName not in self.__knownAuths:
            if isinstance(authData, CommunityData):
                config.addV1System(
                    self.snmpEngine,
                    authData.securityName,
                    authData.communityName,
                    authData.contextEngineId,
                    authData.contextName,
                    authData.tag
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

            self.__knownAuths[authData.securityName] = authData

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

        k = paramsName, transportTarget, transportTarget.tagList

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
                transportTarget.tagList
            )
            self.__knownTransportAddrs[k] = addrName

        return addrName, paramsName

    def uncfgCmdGen(self):
        for authData in self.__knownAuths.values():
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
                
    def makeReadVarBinds(self, varNames):
        varBinds = []
        for varName in varNames:
            if isinstance(varName, MibVariable):
                varName.resolveWithMib(
                    self.mibViewController, oidOnly=True
                )
            elif isinstance(varName[0], tuple):  # legacy
                varName = MibVariable(varName[0][0], varName[0][1], *varName[1:]).resolveWithMib(self.mibViewController)
            else:
                varName = MibVariable(varName).resolveWithMib(self.mibViewController, oidOnly=True)
            varBinds.append((varName, self._null))
        return varBinds

    def unmakeVarBinds(self, varBinds, lookupNames, lookupValues):
        if lookupNames or lookupValues:
            _varBinds = []
            for name, value in varBinds:
                varName = MibVariable(name).resolveWithMib(self.mibViewController)
                if lookupNames:
                    name = varName
                if lookupValues:
                    if value.tagSet not in (rfc1905.NoSuchObject.tagSet,
                                            rfc1905.NoSuchInstance.tagSet,
                                            rfc1905.EndOfMibView.tagSet):
                        if varName.isFullyResolved():
                            value = varName.getMibNode().getSyntax().clone(value)
                _varBinds.append((name, value))
            return _varBinds
        else:
            return varBinds

    # Async SNMP apps

    def getCmd(self, authData, transportTarget, varNames, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.unmakeVarBinds(varBinds, lookupNames, lookupValues),
                cbCtx
            )

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
        )

        return cmdgen.GetCommandGenerator().sendReq(
            self.snmpEngine,
            addrName,
            self.makeReadVarBinds(varNames),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx),
            contextEngineId, contextName
        )
    
    asyncGetCmd = getCmd
    
    def setCmd(self, authData, transportTarget, varBinds, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.unmakeVarBinds(varBinds, lookupNames, lookupValues),
                cbCtx
            )

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
        )
        __varBinds = []
        for varName, varVal in varBinds:
            if isinstance(varName, MibVariable):
                varName.resolveWithMib(self.mibViewController)
                if not isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varVal = varName.getMibNode().getSyntax().clone(varVal)
            elif isinstance(varName[0], tuple):  # legacy
                varName = MibVariable(varName[0][0], varName[0][1], *varName[1:]).resolveWithMib(self.mibViewController)
                if not isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varVal = varName.getMibNode().getSyntax().clone(varVal)
            else:
                if isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varName = MibVariable(varName).resolveWithMib(self.mibViewController, oidOnly=True)
                else:
                    varName = MibVariable(varName).resolveWithMib(self.mibViewController)
                    varVal = varName.getMibNode().getSyntax().clone(varVal)

            __varBinds.append((varName, varVal))
        return cmdgen.SetCommandGenerator().sendReq(
            self.snmpEngine,
            addrName,
            __varBinds,
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx),
            contextEngineId, contextName
        )
    
    asyncSetCmd = setCmd
    
    def nextCmd(self, authData, transportTarget, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.unmakeVarBinds(varBindTableRow, lookupNames, lookupValues) for varBindTableRow in varBindTable ],
                cbCtx
            )

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
        )
        return cmdgen.NextCommandGenerator().sendReq(
            self.snmpEngine,
            addrName,
            self.makeReadVarBinds(varNames),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx),
            contextEngineId, contextName
        )

    asyncNextCmd = nextCmd
    
    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.unmakeVarBinds(varBindTableRow, lookupNames, lookupValues) for varBindTableRow in varBindTable ],
                cbCtx
            )

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            authData, transportTarget
        )
        varBinds = self.makeReadVarBinds(varNames)
        return cmdgen.BulkCommandGenerator().sendReq(
            self.snmpEngine,
            addrName,
            nonRepeaters, maxRepetitions,
            varBinds,
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx),
            contextEngineId, contextName
        )

    asyncBulkCmd = bulkCmd

class CommandGenerator:
    def __init__(self, snmpEngine=None, asynCmdGen=None):
        if asynCmdGen is None:
            self.__asynCmdGen = AsynCommandGenerator(snmpEngine)
        else:
            self.__asynCmdGen = asynCmdGen

        # compatibility attributes
        self.snmpEngine = self.__asynCmdGen.snmpEngine
        self.mibViewController = self.__asynCmdGen.mibViewController
       
    def getCmd(self, authData, transportTarget, *varNames, **kwargs):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, appReturn):
            appReturn['errorIndication'] = errorIndication
            appReturn['errorStatus'] = errorStatus
            appReturn['errorIndex'] = errorIndex
            appReturn['varBinds'] = varBinds

        appReturn = {}
        self.__asynCmdGen.getCmd(
            authData,
            transportTarget,
            varNames,
            (__cbFun, appReturn),
            kwargs.get('lookupNames', False),
            kwargs.get('lookupValues', False),
            kwargs.get('contextEngineId'),
            kwargs.get('contextName', null)
        )
        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds']
        )

    def setCmd(self, authData, transportTarget, *varBinds, **kwargs):
        def __cbFun(sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, appReturn):
            appReturn['errorIndication'] = errorIndication
            appReturn['errorStatus'] = errorStatus
            appReturn['errorIndex'] = errorIndex
            appReturn['varBinds'] = varBinds

        appReturn = {}
        self.__asynCmdGen.setCmd(
            authData,
            transportTarget,
            varBinds,
            (__cbFun, appReturn),
            kwargs.get('lookupNames', False),
            kwargs.get('lookupValues', False),
            kwargs.get('contextEngineId'),
            kwargs.get('contextName', null)
        )
        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds']
        )

    def nextCmd(self, authData, transportTarget, *varNames, **kwargs):
        def __cbFun(sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBindTable, cbCtx):
            (self, varBindHead, varBindTotalTable, appReturn) = cbCtx
            if (ignoreNonIncreasingOid or \
                        hasattr(self, 'ignoreNonIncreasingOid') and \
                        self.ignoreNonIncreasingOid ) and \
                    errorIndication and \
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
                if maxRows and len(varBindTotalTable) >= maxRows or \
                        hasattr(self, 'maxRows') and self.maxRows and \
                        len(varBindTotalTable) >= self.maxRows:
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    if hasattr(self, 'maxRows'):
                        appReturn['varBindTable'] = varBindTotalTable[:self.maxRows]
                    else:
                        appReturn['varBindTable'] = varBindTotalTable[:maxRows]
                    return
                
                varBindTableRow = varBindTable and varBindTable[-1] or varBindTable
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    # XXX extra rows
                    if not isinstance(val, univ.Null):
                        if lexicographicMode or \
                               hasattr(self, 'lexicographicMode') and \
                               self.lexicographicMode:  # obsolete
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

        lookupNames = kwargs.get('lookupNames', False)        
        lookupValues = kwargs.get('lookupValues', False)
        contextEngineId = kwargs.get('contextEngineId')
        contextName = kwargs.get('contextName', null)
        lexicographicMode = kwargs.get('lexicographicMode', False)
        maxRows = kwargs.get('maxRows', 0)
        ignoreNonIncreasingOid = kwargs.get('ignoreNonIncreasingOid', False)

        varBindHead = [ univ.ObjectIdentifier(x[0]) for x in self.__asynCmdGen.makeReadVarBinds(varNames) ]

        appReturn = {}
        self.__asynCmdGen.nextCmd(
            authData,
            transportTarget,
            varNames,
            (__cbFun, (self, varBindHead, [], appReturn)),
            lookupNames, lookupValues,
            contextEngineId, contextName
        )

        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
        )

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, *varNames, **kwargs):
        def __cbFun(sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBindTable, cbCtx):
            (self, varBindHead, varBindTotalTable, appReturn) = cbCtx
            if (ignoreNonIncreasingOid or \
                        hasattr(self, 'ignoreNonIncreasingOid') and \
                        self.ignoreNonIncreasingOid ) and \
                    errorIndication and \
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

                if maxRows and len(varBindTotalTable) >= maxRows or \
                        hasattr(self, 'maxRows') and self.maxRows and \
                        len(varBindTotalTable) >= self.maxRows:  # obsolete
                    appReturn['errorIndication'] = errorIndication
                    appReturn['errorStatus'] = errorStatus
                    appReturn['errorIndex'] = errorIndex
                    if hasattr(self, 'maxRows'):
                        appReturn['varBindTable'] = varBindTotalTable[:self.maxRows]
                    else:
                        appReturn['varBindTable'] = varBindTotalTable[:maxRows]
                    return

                varBindTableRow = varBindTable and varBindTable[-1] or varBindTable
                for idx in range(len(varBindTableRow)):
                    name, val = varBindTableRow[idx]
                    if not isinstance(val, univ.Null):
                        if lexicographicMode or \
                               hasattr(self, 'lexicographicMode') and \
                               self.lexicographicMode:  # obsolete
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

        lookupNames = kwargs.get('lookupNames', False)        
        lookupValues = kwargs.get('lookupValues', False)
        contextEngineId = kwargs.get('contextEngineId')
        contextName = kwargs.get('contextName', null)
        lexicographicMode = kwargs.get('lexicographicMode', False)
        maxRows = kwargs.get('maxRows', 0)
        ignoreNonIncreasingOid = kwargs.get('ignoreNonIncreasingOid', False)

        varBindHead = [ univ.ObjectIdentifier(x[0]) for x in self.__asynCmdGen.makeReadVarBinds(varNames) ]

        appReturn = {}
        
        self.__asynCmdGen.bulkCmd(
            authData,
            transportTarget,
            nonRepeaters, maxRepetitions,
            varNames,
            (__cbFun, (self, varBindHead, [], appReturn)),
            lookupNames, lookupValues,
            contextEngineId, contextName
        )

        self.__asynCmdGen.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
        )
