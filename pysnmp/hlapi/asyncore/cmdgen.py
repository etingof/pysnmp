from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from pysnmp.entity.rfc3413.oneliner.auth import CommunityData, UsmUserData
from pysnmp.entity.rfc3413.oneliner.target import UdpTransportTarget, \
    Udp6TransportTarget, UnixTransportTarget
from pysnmp.entity.rfc3413.oneliner.ctx import ContextData
from pysnmp.proto import rfc1905, errind
from pysnmp.smi import view
from pysnmp import nextid, error
from pyasn1.type import univ, base
from pyasn1.compat.octets import null
# obsolete, compatibility symbols
from pysnmp.entity.rfc3413.oneliner.mibvar import MibVariable

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

class AsyncCommandGenerator:
    _null = univ.Null('')

    def _getCache(self, snmpEngine):
        cache = snmpEngine.getUserContext('cmdgen_cache')
        if cache is None:
            cache = {
                'auth': {}, 'parm': {}, 'tran': {}, 'addr': {}
            }
            snmpEngine.setUserContext(cmdgen_cache=cache)
        return cache

    def getMibViewController(self, snmpEngine):
        mibViewController = snmpEngine.getUserContext('mibViewController')
        if not mibViewController:
            mibViewController = view.MibViewController(
                snmpEngine.getMibBuilder()
            )
            snmpEngine.setUserContext(mibViewController=mibViewController)
        return mibViewController
        
    def cfgCmdGen(self, snmpEngine, authData, transportTarget):
        cache = self._getCache(snmpEngine)
        if isinstance(authData, CommunityData):
            if authData.communityIndex not in cache['auth']:
                config.addV1System(
                    snmpEngine,
                    authData.communityIndex,
                    authData.communityName,
                    authData.contextEngineId,
                    authData.contextName,
                    authData.tag,
                    authData.securityName
                )
                cache['auth'][authData.communityIndex] = authData
        elif isinstance(authData, UsmUserData):
            authDataKey = authData.userName, authData.securityEngineId
            if authDataKey not in cache['auth']:
                config.addV3User(
                    snmpEngine,
                    authData.userName,
                    authData.authProtocol, authData.authKey,
                    authData.privProtocol, authData.privKey,
                    authData.securityEngineId,
                    securityName=authData.securityName
                )
                cache['auth'][authDataKey] = authData
        else:
            raise error.PySnmpError('Unsupported authentication object')

        paramsKey = authData.securityName, \
                    authData.securityLevel, \
                    authData.mpModel
        if paramsKey in cache['parm']:
            paramsName, useCount = cache['parm'][paramsKey]
            cache['parm'][paramsKey] = paramsName, useCount + 1
        else:
            paramsName = 'p%s' % nextID()
            config.addTargetParams(
                snmpEngine, paramsName,
                authData.securityName, authData.securityLevel, authData.mpModel
            )
            cache['parm'][paramsKey] = paramsName, 1

        if transportTarget.transportDomain in cache['tran']:
            transport, useCount = cache['tran'][transportTarget.transportDomain]
            transportTarget.verifyDispatcherCompatibility(snmpEngine)
            cache['tran'][transportTarget.transportDomain] = transport, useCount + 1
        elif config.getTransport(snmpEngine, transportTarget.transportDomain):
            transportTarget.verifyDispatcherCompatibility(snmpEngine)
        else:
            transport = transportTarget.openClientMode()
            config.addTransport(
                snmpEngine,
                transportTarget.transportDomain,
                transport
            )
            cache['tran'][transportTarget.transportDomain] = transport, 1

        transportKey = ( paramsName,
                         transportTarget.transportDomain,
                         transportTarget.transportAddr,
                         transportTarget.tagList )

        if transportKey in cache['addr']:
            addrName, useCount = cache['addr'][transportKey]
            cache['addr'][transportKey] = addrName, useCount + 1
        else:
            addrName = 'a%s' % nextID()
            config.addTargetAddr(
                snmpEngine, addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName,
                transportTarget.timeout * 100,
                transportTarget.retries,
                transportTarget.tagList
            )
            cache['addr'][transportKey] = addrName, 1

        return addrName, paramsName

    def uncfgCmdGen(self, snmpEngine, authData=None):
        cache = self._getCache(snmpEngine)
        if authData:
            if isinstance(authData, CommunityData):
                authDataKey = authData.communityIndex
            elif isinstance(authData, UsmUserData):
                authDataKey = authData.userName, authData.securityEngineId
            else:
                raise error.PySnmpError('Unsupported authentication object')
            if authDataKey in cache['auth']:
                authDataKeys = ( authDataKey, )
            else:
                raise error.PySnmpError('Unknown authData %s' % (authData,))
        else:
            authDataKeys = list(cache['auth'].keys())

        addrNames, paramsNames = set(), set()

        for authDataKey in authDataKeys:
            authDataX = cache['auth'][authDataKey] 
            del cache['auth'][authDataKey]
            if isinstance(authDataX, CommunityData):
                config.delV1System(
                    snmpEngine,
                    authDataX.communityIndex
                )
            elif isinstance(authDataX, UsmUserData):
                config.delV3User(
                    snmpEngine,
                    authDataX.userName, 
                    authDataX.securityEngineId
                )
            else:
                raise error.PySnmpError('Unsupported authentication object')

            paramsKey = authDataX.securityName, \
                        authDataX.securityLevel, \
                        authDataX.mpModel
            if paramsKey in cache['parm']:
                paramsName, useCount = cache['parm'][paramsKey]
                useCount -= 1
                if useCount:
                    cache['parm'][paramsKey] = paramsName, useCount
                else:
                    del cache['parm'][paramsKey]
                    config.delTargetParams(
                        snmpEngine, paramsName
                    )
                    paramsNames.add(paramsName)
            else:
                raise error.PySnmpError('Unknown target %s' % (paramsKey,))

            addrKeys = [ x for x in cache['addr'] if x[0] == paramsName ]

            for addrKey in addrKeys:
                addrName, useCount = cache['addr'][addrKey]
                useCount -= 1
                if useCount:
                    cache['addr'][addrKey] = addrName, useCount
                else:
                    config.delTargetAddr(snmpEngine, addrName)

                    addrNames.add(addrKey)

                    if addrKey[1] in cache['tran']:
                        transport, useCount = cache['tran'][addrKey[1]]
                        if useCount > 1:
                            useCount -= 1
                            cache['tran'][addrKey[1]] = transport, useCount
                        else:
                            config.delTransport(snmpEngine, addrKey[1])
                            transport.closeTransport()
                            del cache['tran'][addrKey[1]]

        return addrNames, paramsNames

    def makeVarBinds(self, snmpEngine, varBinds):
        mibViewController = self.getMibViewController(snmpEngine)
        __varBinds = []
        for varBind in varBinds:
            if isinstance(varBind, ObjectType):
                pass
            elif isinstance(varBind[0], ObjectIdentity):
                varBind = ObjectType(*varBind)
            elif isinstance(varBind[0][0], tuple):  # legacy
                varBind = ObjectType(ObjectIdentity(varBind[0][0][0], varBind[0][0][1], *varBind[0][1:]), varBind[1])
            else:
                varBind = ObjectType(ObjectIdentity(varBind[0]), varBind[1])

            __varBinds.append(varBind.resolveWithMib(mibViewController))

        return __varBinds

    def unmakeVarBinds(self, snmpEngine, varBinds, lookupNames, lookupValues):
        if lookupNames or lookupValues:
            mibViewController = self.getMibViewController(snmpEngine)
            varBinds = [ ObjectType(ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds ]

        return varBinds

    def makeVarBindsHead(self, snmpEngine, varNames):
        return [ 
            x[0] for x in self.makeVarBinds(
                snmpEngine,
                [ (x, univ.Null('')) for x in varNames ]
            )
        ]

    # Async SNMP apps

    def getCmd(self, snmpEngine, authData, transportTarget, contextData, 
               varNames, cbInfo, lookupNames=False, lookupValues=False):
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupNames, lookupValues
                ),
                cbCtx
            )
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.GetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.makeVarBinds(snmpEngine, [(x, self._null) for x in varNames]),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx)
        )
    
    def setCmd(self, snmpEngine, authData, transportTarget, contextData,
               varBinds, cbInfo, lookupNames=False, lookupValues=False):
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupNames, lookupValues
                ),
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.SetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx)
        )
    
    def nextCmd(self, snmpEngine, authData, transportTarget, contextData,
                varNames, cbInfo, lookupNames=False, lookupValues=False):
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.unmakeVarBinds(snmpEngine, varBindTableRow, lookupNames, lookupValues) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.NextCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId, contextData.contextName,
            self.makeVarBinds(snmpEngine, [(x, self._null) for x in varNames]),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx)
        )

    def bulkCmd(self, snmpEngine, authData, transportTarget, contextData,
                nonRepeaters, maxRepetitions, varNames, cbInfo,
                lookupNames=False, lookupValues=False):
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.unmakeVarBinds(snmpEngine, varBindTableRow, lookupNames, lookupValues) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.BulkCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            nonRepeaters, maxRepetitions,
            self.makeVarBinds(snmpEngine, [(x, self._null) for x in varNames]),
            __cbFun,
            (lookupNames, lookupValues, cbFun, cbCtx)
        )

# compatibility implementation, never use this class for new applications
class AsynCommandGenerator:
    def __init__(self, snmpEngine=None):
        if snmpEngine is None:
            self.snmpEngine = snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine

        self.__asyncCmdGen = AsyncCommandGenerator()
        self.mibViewController = self.__asyncCmdGen.getMibViewController(self.snmpEngine)

    def __del__(self):
        self.__asyncCmdGen.uncfgCmdGen(self.snmpEngine)

    def cfgCmdGen(self, authData, transportTarget):
        return self.__asyncCmdGen.cfgCmdGen(
            self.snmpEngine, authData, transportTarget
        )

    def uncfgCmdGen(self, authData=None):
        return self.__asyncCmdGen.uncfgCmdGen(
            self.snmpEngine, authData
        )

    # compatibility stub
    def makeReadVarBinds(self, varNames):
        return self.makeVarBinds(
            [ (x, univ.Null('')) for x in varNames ]
        )

    def makeVarBinds(self, varBinds):
        return self.__asyncCmdGen.makeVarBinds(
            self.snmpEngine, varBinds
        )

    def unmakeVarBinds(self, varBinds, lookupNames, lookupValues):
        return self.__asyncCmdGen.unmakeVarBinds(
            self.snmpEngine, varBinds, lookupNames, lookupValues
        )

    def getCmd(self, authData, transportTarget, varNames, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            cbFun(sendRequestHandle,
                  errorIndication, errorStatus, errorIndex,
                  varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.getCmd(
            self.snmpEngine, 
            authData, transportTarget,
            ContextData(contextEngineId, contextName), varNames, cbInfo,
            lookupNames, lookupValues
        )

    asyncGetCmd = getCmd

    def setCmd(self, authData, transportTarget, varBinds, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            cbFun(sendRequestHandle,
                  errorIndication, errorStatus, errorIndex,
                  varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo
        
        return self.__asyncCmdGen.setCmd(
            self.snmpEngine,
            authData, transportTarget,
            ContextData(contextEngineId, contextName), varBinds, cbInfo,
            lookupNames, lookupValues
        )

    asyncSetCmd = setCmd

    def nextCmd(self, authData, transportTarget, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            return cbFun(sendRequestHandle,
                         errorIndication, errorStatus, errorIndex,
                         varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.nextCmd(
            self.snmpEngine,
            authData, transportTarget,
            ContextData(contextEngineId, contextName), varNames, cbInfo,
            lookupNames, lookupValues
        )

    asyncNextCmd = nextCmd

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            return cbFun(sendRequestHandle,
                         errorIndication, errorStatus, errorIndex,
                         varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.bulkCmd(
            self.snmpEngine, 
            authData, transportTarget,
            ContextData(contextEngineId, contextName),
            nonRepeaters, maxRepetitions,
            varNames, cbInfo,
            lookupNames, lookupValues
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
        self.snmpEngine.transportDispatcher.runDispatcher()
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
        self.snmpEngine.transportDispatcher.runDispatcher()
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
 
                if maxCalls[0] > 0:
                    maxCalls[0] -= 1
                    if maxCalls[0] == 0:
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
        maxCalls = [ kwargs.get('maxCalls', 0) ]
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
        self.snmpEngine.transportDispatcher.runDispatcher()
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
            (self, varBindHead, nullVarBinds, varBindTotalTable, appReturn) = cbCtx
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
                stopFlag = False
                if not lexicographicMode:  # cut possible extra OIDs
                    stopFlag = True
                    for i in range(len(varBindTable)):
                        stopFlag = True
                        if len(varBindTable[i]) != len(varBindHead):
                            varBindTable = i and varBindTable[:i-1] or []
                            break
                        for j in range(len(varBindTable[i])): # dichotomy?
                            name, val = varBindTable[i][j]
                            if nullVarBinds[j]:
                                varBindTable[i][j] = name, rfc1905.endOfMibView
                                continue
                            stopFlag = False
                            if not isinstance(val, univ.Null):
                                if not varBindHead[j].isPrefixOf(name):
                                    varBindTable[i][j] = name, rfc1905.endOfMibView
                                    nullVarBinds[j] = True
                        if stopFlag:
                            varBindTable = i and varBindTable[:i-1] or []
                            break

                varBindTotalTable.extend(varBindTable)

                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBindTable'] = varBindTotalTable

                if maxCalls[0] > 0:
                    maxCalls[0] -= 1
                    if maxCalls[0] == 0:
                      return
 
                if maxRows and len(varBindTotalTable) >= maxRows or \
                        hasattr(self, 'maxRows') and self.maxRows and \
                        len(varBindTotalTable) >= self.maxRows:  # obsolete
                    if hasattr(self, 'maxRows'):
                        appReturn['varBindTable'] = varBindTotalTable[:self.maxRows]
                    else:
                        appReturn['varBindTable'] = varBindTotalTable[:maxRows]
                    return

                return not stopFlag    # continue table retrieval

        lookupNames = kwargs.get('lookupNames', False)        
        lookupValues = kwargs.get('lookupValues', False)
        contextEngineId = kwargs.get('contextEngineId')
        contextName = kwargs.get('contextName', null)
        lexicographicMode = kwargs.get('lexicographicMode', False)
        if not lexicographicMode: # obsolete
            if hasattr(self, 'lexicographicMode') and self.lexicographicMode:
                lexicographicMode = True
        maxRows = kwargs.get('maxRows', 0)
        maxCalls = [ kwargs.get('maxCalls', 0) ]
        ignoreNonIncreasingOid = kwargs.get('ignoreNonIncreasingOid', False)

        varBindHead = [ univ.ObjectIdentifier(x[0]) for x in self.__asynCmdGen.makeReadVarBinds(varNames) ]
        nullVarBinds = [ False ] * len(varBindHead)

        appReturn = {}
        
        self.__asynCmdGen.bulkCmd(
            authData,
            transportTarget,
            nonRepeaters, maxRepetitions,
            varNames,
            (__cbFun, (self, varBindHead, nullVarBinds, [], appReturn)),
            lookupNames, lookupValues,
            contextEngineId, contextName
        )

        self.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBindTable']
        )
