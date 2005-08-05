import socket, string, types
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen, mibvar
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import view
from pysnmp import error
from pyasn1.type import univ

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
    authKey = privKey = None
    securityLevel='noAuthNoPriv'
    securityModel=3
    mpModel=2
    authProtocol = privProtocol = None
    def __init__(self, securityName, authKey=None, authProtocol='md5',
                 privKey=None, privProtocol='des'):
        self.securityName = securityName
        if authKey is not None:
            self.authKey = authKey
            self.authProtocol = authProtocol
            if self.securityLevel != 'authPriv':
                self.securityLevel = 'authNoPriv'
        if privKey is not None:
            self.privKey = privKey
            self.securityLevel = 'authPriv'
            self.privProtocol = privProtocol

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

    def __configure(self, authData, transportTarget):
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
                    authData.authKey, authData.authProtocol,
                    authData.privKey, authData.privProtocol
                    )
                config.addTargetParams(
                    self.snmpEngine, paramsName,
                    authData.securityName, authData.securityLevel
                    )
            else:
                raise error.PySnmpError('Unsupported SNMP version')
            self.__knownAuths[authData] = 1

        addrName = str(transportTarget.transportAddr)
        if not self.__knownTransports.has_key(transportTarget):
            config.addSocketTransport(
                self.snmpEngine,
                transportTarget.transportDomain,
                transportTarget.transport
                )
            self.__knownTransports[transportTarget] = 1
    
            config.addTargetAddr(
                self.snmpEngine, addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName
                )
        return addrName

    # Async SNMP apps
    
    def asyncGetCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName = self.__configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.instanceNameToOid(
                self.mibViewController, varName
                )
            varBinds.append((name + oid, self._null))
        return cmdgen.GetCommandGenerator().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx
            )

    def asyncNextCmd(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName = self.__configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.instanceNameToOid(
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
        addrName = self.__configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            name, oid = mibvar.instanceNameToOid(
                self.mibViewController, varName
                )
            varBinds.append((name + oid, self._null))
        return cmdgen.BulkCommandGenerator().sendReq(
            self.snmpEngine, addrName, nonRepeaters, maxRepetitions,
            varBinds, cbFun, cbCtx
            )

    def asyncSetCmd(self): pass

class CommandGenerator(AsynCommandGenerator):
    def __cbFun(
        self, sendRequestHandle, errorIndication, errorStatus, errorIndex,
        varBinds, appReturn
        ):
        appReturn['errorIndication'] = errorIndication
        appReturn['errorStatus'] = errorStatus
        appReturn['errorIndex'] = errorIndex
        appReturn['varBinds'] = varBinds
        
    def getCmd(self, authData, transportTarget, *varNames):
        appReturn = {}
        self.asyncGetCmd(
            authData, transportTarget, varNames, (self.__cbFun, appReturn)
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
                if varBindTable:
                    varBinds=varBindTable[-1]
                else:
                    varBinds = []
                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBinds'] = varBinds
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
                    appReturn['varBinds'] = varBindTable[-1],
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                varBindTotalTable.extend(varBindTable)

            return 1 # continue table retrieval
        
        head = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.instanceNameToOid(self.mibViewController, x), varNames))

        appReturn = {}
        self.asyncNextCmd(
            authData, transportTarget, varNames, (__cbFun, (head,[],appReturn))
            )

        self.snmpEngine.transportDispatcher.runDispatcher()

        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds'],
            appReturn['varBindTable']
            )

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, *varNames):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBindTable, (varBindHead, varBindTotalTable, appReturn)
            ):
            if errorIndication or errorStatus:
                if varBindTable:
                    varBinds=varBindTable[-1]
                else:
                    varBinds = []
                appReturn['errorIndication'] = errorIndication
                appReturn['errorStatus'] = errorStatus
                appReturn['errorIndex'] = errorIndex
                appReturn['varBinds'] = varBinds
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
                    appReturn['varBinds'] = varBindTable[-1],
                    appReturn['varBindTable'] = varBindTotalTable
                    return
                
            return 1 # continue table retrieval
        
        head = map(lambda (x,y): univ.ObjectIdentifier(x+y), map(lambda x,self=self: mibvar.instanceNameToOid(self.mibViewController, x), varNames))
                   
        self.asyncBulkCmd(
            authData, transportTarget, nonRepeaters, maxRepetitions,
            varNames, (__cbFun, (head, [], appReturn))
            )

        self.snmpEngine.transportDispatcher.runDispatcher()
        
        return (
            appReturn['errorIndication'],
            appReturn['errorStatus'],
            appReturn['errorIndex'],
            appReturn['varBinds'],
            appReturn['varBindTable']
            )
