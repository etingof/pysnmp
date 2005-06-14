import socket, string, types
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import view
from pysnmp.entity.rfc3413.error import ApplicationReturn
from pysnmp import error
from pyasn1.type import univ

class CommunityData: pass

class UsmUserData:
    authKey = privKey = None
    securityLevel='noAuthNoPriv'
    authProtocol='md5'
    privProtocol='des'
    def __init__(self, securityName, authKey=None, privKey=None):
        self.securityName = securityName
        if authKey is not None:
            self.authKey = authKey
            if self.securityLevel != 'authPriv':
                self.securityLevel = 'authNoPriv'
        if privKey is not None:
            self.privKey = privKey
            self.securityLevel = 'authPriv'

class UdpTransportTarget:
    transportDomain = udp.domainName
    transport = udp.UdpSocketTransport().openClientMode()
    retries = timeout = None  # XXX
    def __init__(self, transportAddr):
        self.transportAddr = (
            socket.gethostbyname(transportAddr[0]), transportAddr[1]
            )

class AsynCmdGen:
    _null = univ.Null()
    def __init__(self, snmpEngine=None):
        if snmpEngine is None:
            self.snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine
        self.mibView = view.MibViewController(
            self.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
            )
        self.__knownAuths = {}
        self.__knownTransports = {}

    def __configure(self, authData, transportTarget):
        paramsName = '%s-params' % (authData.securityName,)
        if not self.__knownAuths.has_key(authData):
            if isinstance(authData, CommunityData):
                # XXX
                config.addV1System(self.snmpEngine, authData.communityName)
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

    # OID filters
    
    def prettyNameToOid(self, varName):
        if string.find(varName, '::') == -1:
            modName, symName = '', varName
        else:
            modName, symName = string.split(varName, '::')
            self.mibView.loadMissingModule(modName)
        __n = string.split(symName, '.')  # XXX support index spec
        oid, label, suffix = self.mibView.getNodeName(__n[0], modName)
        newSymName = []; newSymName.extend(oid); newSymName.extend(suffix)
        for subName in __n[1:]:
            try:
                newSymName.append(string.atol(subName))
            except ValueError:
                raise error.PySnmpError('Unexpected name suffix %s' % (__n,))
        return tuple(newSymName)

    def oidToPrettyName(self, oid):
        modName, symName, suffix = self.mibView.getNodeLocation(tuple(oid))
        mibNode, = self.mibView.mibBuilder.importSymbols(modName, symName)
        symName = '%s.%s' % (
            symName, string.join(map(str, suffix), '.')
            )
        return (modName, symName)

    def makePrettyValue(self, value): pass
    def makeNativeValue(self, value): pass
    
    def asyncSnmpGet(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName = self.__configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            if type(varName) == types.StringType:
                oid = self.prettyNameToOid(varName)
            else:
                oid, label, suffix = self.mibView.getNodeName(varName)
                oid = oid + suffix
            varBinds.append((oid, self._null))
        return cmdgen.SnmpGet().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx
            )

    def asyncSnmpWalk(
        self, authData, transportTarget, varNames, (cbFun, cbCtx)
        ):
        addrName = self.__configure(
            authData, transportTarget
            )
        varBinds = []
        for varName in varNames:
            if type(varName) == types.StringType:
                oid = self.prettyNameToOid(varName)
            else:
                oid, label, suffix = self.mibView.getNodeName(varName)
                oid = oid + suffix
            varBinds.append((oid, self._null))
        return cmdgen.SnmpWalk().sendReq(
            self.snmpEngine, addrName, varBinds, cbFun, cbCtx
            )

    def snmpTable(self): pass
    def snmpSet(self): pass
    def snmpBulkWalk(self): pass

class CmdGen(AsynCmdGen):
    def __cbFun(
        self, sendRequestHandle, errorIndication, errorStatus, errorIndex,
        varBinds, cbCtx
        ):
        raise ApplicationReturn(
            errorIndication=errorIndication,
            errorStatus=errorStatus,
            errorIndex=errorIndex,
            varBinds=varBinds
            )
        
    def snmpGet(self, authData, transportTarget, *varNames):
        self.asyncSnmpGet(
            authData, transportTarget, varNames, (self.__cbFun, None)
            )
        try:
            self.snmpEngine.transportDispatcher.runDispatcher()
        except ApplicationReturn, applicationReturn:
            return (
                applicationReturn['errorIndication'],
                applicationReturn['errorStatus'],
                applicationReturn['errorIndex'],
                applicationReturn['varBinds']
                )

    def snmpWalk(self, authData, transportTarget, *varNames):
        def __cbFun(
            sendRequestHandle, errorIndication, errorStatus, errorIndex,
            varBinds, (varBindHead, varBindTable)
            ):
            if errorIndication or errorStatus:
                raise ApplicationReturn(
                    errorIndication=errorIndication,
                    errorStatus=errorStatus,
                    errorIndex=errorIndex,
                    varBinds=varBinds,
                    varBindTable=varBindTable
                    )
            else:
                for idx in range(len(varBinds)):
                    name, val = varBinds[idx]
                    if head[idx].isPrefixOf(name):
                        break
                else:
                    raise ApplicationReturn(
                        errorIndication=errorIndication,
                        errorStatus=errorStatus,
                        errorIndex=errorIndex,
                        varBinds=varBinds,
                        varBindTable=varBindTable
                        )
                varBindTable.extend(varBinds)

        head = map(
            lambda x,self=self: univ.ObjectIdentifier(self.prettyNameToOid(x)),
            varNames
            )

        self.asyncSnmpWalk(
            authData, transportTarget, varNames, (__cbFun, (head, []))
            )
        try:
            while 1:
                self.snmpEngine.transportDispatcher.runDispatcher()
        except ApplicationReturn, applicationReturn:
            return (
                applicationReturn['errorIndication'],
                applicationReturn['errorStatus'],
                applicationReturn['errorIndex'],
                applicationReturn['varBinds'],
                applicationReturn['varBindTable'],
                )
    
# XXX
# unify cb params passing
# how to stop walkng a tree at oneliners?
# rename oneliner
# some method for params passing other than exception?
# implement SMI indices handling
# speed up key localization
# implement snmpbulk oneliner
# get snmpv1 back to life
