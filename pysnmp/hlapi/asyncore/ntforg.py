from pyasn1.compat.octets import null
from pysnmp import nextid, error
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.entity.rfc3413.oneliner.mibvar import MibVariable
from pysnmp.entity.rfc3413.oneliner.auth import CommunityData, UsmUserData
from pysnmp.entity.rfc3413.oneliner.target import UdpTransportTarget, \
    Udp6TransportTarget, UnixTransportTarget 
from pysnmp.entity.rfc3413.oneliner import cmdgen

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

class AsyncNotificationOriginator(cmdgen.AsyncCommandGenerator):
    def _getNtfCache(self, snmpEngine):
        if 'ntforg' not in snmpEngine.cache:
            snmpEngine.cache['ntforg'] = { 
                'auth': {},
                'name': {}
           }
        return snmpEngine.cache['ntforg']
        
    def cfgNtfOrg(self, snmpEngine, authData, transportTarget, notifyType):
        cache = self._getNtfCache(snmpEngine)
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )
        tagList = transportTarget.tagList.split()
        if not tagList:
            tagList = ['']
        for tag in tagList:
            notifyNameKey = paramsName, tag, notifyType
            if notifyNameKey in cache['name']:
                notifyName, paramsName, useCount = cache['name'][notifyNameKey]
                cache['name'][notifyNameKey] = notifyName, paramsName, useCount + 1
            else:
                notifyName = 'n%s' % nextID()
                config.addNotificationTarget(
                    snmpEngine,
                    notifyName,
                    paramsName,
                    tag,
                    notifyType
                )
                cache['name'][notifyNameKey] = notifyName, paramsName, 1
        authDataKey = authData.securityName, authData.securityModel
        if  authDataKey in cache['auth']:
            authDataX, subTree, useCount = cache['auth'][authDataKey]
            cache['auth'][authDataKey] = authDataX, subTree, useCount + 1
        else:
            subTree = (1,3,6)
            config.addTrapUser(
                snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree
            )
            cache['auth'][authDataKey] = authData, subTree, 1

        return notifyName
    
    def uncfgNtfOrg(self, snmpEngine, authData=None):
        cache = self._getNtfCache(snmpEngine)
        if authData:
            authDataKey = authData.securityName, authData.securityModel
            if authDataKey in cache['auth']:
                authDataKeys = ( authDataKey, )
            else:
                raise error.PySnmpError('Unknown authData %s' % (authData,))
        else:
            authDataKeys = cache['auth'].keys()

        addrNames, paramsNames = self.uncfgCmdGen(snmpEngine, authData)

        notifyAndParamsNames = [ (cache['name'][x], x) for x in cache['name'].keys() if x[0] in paramsNames ]

        for (notifyName, paramsName, useCount), notifyNameKey in notifyAndParamsNames:
            useCount -= 1
            if useCount:
                cache['name'][notifyNameKey] = notifyName, paramsName, useCount
            else:
                config.delNotificationTarget(
                    snmpEngine, notifyName, paramsName
                )
                del cache['name'][notifyNameKey]

        for authDataKey in authDataKeys:
            authDataX, subTree, useCount = cache['auth'][authDataKey]
            useCount -= 1
            if useCount:
                cache['auth'][authDataKey] = authDataX, subTree, useCount
            else:
                config.delTrapUser(
                    snmpEngine,
                    authDataX.securityModel,
                    authDataX.securityName,
                    authDataX.securityLevel,
                    subTree
                )
                del cache['auth'][authDataKey]

    def sendNotification(self, snmpEngine, snmpContext,
                         authData, transportTarget, 
                         notifyType,
                         notificationType, instanceIndex,
                         varBinds=(),
                         cbInfo=(None, None), 
                         lookupNames=False, lookupValues=False,
                         contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            return cbFun and cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus, errorIndex,
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupNames, lookupValues
                ),
                cbCtx
            )

        cache = self._getCmdCache(snmpEngine)

        (cbFun, cbCtx) = cbInfo

        # Create matching transport tags if not given by user
        if not transportTarget.tagList:
            transportTarget.tagList = str(
                hash((authData.securityName, transportTarget.transportAddr))
            )
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        notifyName = self.cfgNtfOrg(
            snmpEngine, authData, transportTarget, notifyType
        )
        if isinstance(notificationType, MibVariable):
            notificationType = notificationType.resolveWithMib(
                cache['mibViewController'], oidOnly=True
            )

        return ntforg.NotificationOriginator().sendVarBinds(snmpEngine, snmpContext, contextName, notifyName, notificationType, instanceIndex, self.makeVarBinds(snmpEngine, varBinds), __cbFun, (lookupNames, lookupValues, cbFun, cbCtx))

# substitute sendNotification return object for backward compatibility
class ErrorIndicationReturn:
    def __init__(self, *vars): self.__vars = vars
    def __getitem__(self, i): return self.__vars[i]
    def __nonzero__(self): return self.__vars[0] and 1 or 0
    def __bool__(self): return bool(self.__vars[0])
    def __str__(self): return str(self.__vars[0])

# compatibility implementation, never use this class for new applications
class AsynNotificationOriginator(cmdgen.AsynCommandGenerator):
    def __init__(self, snmpEngine=None, snmpContext=None):
        cmdgen.AsynCommandGenerator.__init__(self, snmpEngine)
        self.__asyncNtfOrg = AsyncNotificationOriginator()

        # grab/create MibViewController from/for the real AsyncCommandGen
        cache = self.__asyncNtfOrg._getCmdCache(self.snmpEngine)
        self.mibViewController = cache['mibViewController']

        if snmpContext is None:
            self.snmpContext = context.SnmpContext(self.snmpEngine)
            config.addContext(
                self.snmpEngine, ''  # this is leaky
            )
        else:
            self.snmpContext = snmpContext

    def __del__(self): self.uncfgNtfOrg()

    def cfgNtfOrg(self, authData, transportTarget, notifyType):
        return self.__asyncNtfOrg.cfgNtfOrg(
            self.snmpEngine, authData, transportTarget, notifyType
        )

    def uncfgNtfOrg(self, authData=None):
        return self.__asyncNtfOrg.uncfgNtfOrg(self.snmpEngine, authData)
        
    def sendNotification(self, authData, transportTarget, 
                         notifyType, notificationType,
                         varBinds=(),
                         cbInfo=(None, None),
                         lookupNames=False, lookupValues=False,
                         contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBinds, cbCtx):
            cbFun, cbCtx = cbCtx
            try:
                # we need to pass response PDU information to user for INFORMs
                return cbFun and cbFun(
                    sendRequestHandle,
                    errorIndication,
                    errorStatus, errorIndex,
                    varBinds,
                    cbCtx
                )
            except TypeError:
                # a backward compatible way of calling user function
                return cbFun(
                    sendRequestHandle,
                    errorIndication,
                    cbCtx
                )

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        # legacy
        if not isinstance(notificationType, MibVariable) and \
                isinstance(notificationType[0], tuple):
            notificationType = MibVariable(notificationType[0][0], notificationType[0][1], *notificationType[1:]).resolveWithMib(self.mibViewController)

        return self.__asyncNtfOrg.sendNotification(
            self.snmpEngine, self.snmpContext,
            authData, transportTarget,
            notifyType, notificationType, None, varBinds, 
            (__cbFun, cbInfo),
            lookupNames, lookupValues, contextName
        )

    asyncSendNotification = sendNotification

class NotificationOriginator:
    def __init__(self, snmpEngine=None, snmpContext=None, asynNtfOrg=None):
        if asynNtfOrg is None:
            self.__asynNtfOrg = AsynNotificationOriginator(
                snmpEngine, snmpContext
                )
        else:
            self.__asynNtfOrg = asynNtfOrg

    def sendNotification(self, authData, transportTarget, notifyType,
                         notificationType, *varBinds, **kwargs):
        def __cbFun(sendRequestHandle, errorIndication, 
                    errorStatus, errorIndex, varBinds, appReturn):
            appReturn[0] = ErrorIndicationReturn(
                errorIndication, errorStatus, errorIndex, varBinds
            )

        appReturn = { 0: ErrorIndicationReturn(None, 0, 0, ()) }
        self.__asynNtfOrg.sendNotification(
            authData, transportTarget, notifyType, notificationType, 
            varBinds, (__cbFun, appReturn),
            kwargs.get('lookupNames', False),
            kwargs.get('lookupValues', False),
            kwargs.get('contextName', null)
        )
        self.__asynNtfOrg.snmpEngine.transportDispatcher.runDispatcher()
        return appReturn[0]
