from pyasn1.compat.octets import null
from pysnmp import nextid, error
from pysnmp.entity import engine, config
from pysnmp.smi.rfc1902 import *
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.entity.rfc3413.oneliner.auth import *
from pysnmp.entity.rfc3413.oneliner.target import *
from pysnmp.entity.rfc3413.oneliner.ctx import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
# obsolete, compatibility symbols
from pysnmp.entity.rfc3413.oneliner.mibvar import MibVariable

SnmpEngine = engine.SnmpEngine

nextID = nextid.Integer(0xffffffff)

class AsyncNotificationOriginator:
    def __init__(self):
        self.__asyncCmdGen = cmdgen.AsyncCommandGenerator()

    def _getCache(self, snmpEngine):
        cache = snmpEngine.getUserContext('ntforg')
        if cache is None:
            cache = { 'auth': {}, 'name': {} }
            snmpEngine.setUserContext(ntforg=cache)
        return cache

    def getMibViewController(self, snmpEngine):
        return self.__asyncCmdGen.getMibViewController(snmpEngine)
    
    def cfgNtfOrg(self, snmpEngine, authData, transportTarget, notifyType):
        cache = self._getCache(snmpEngine)
        addrName, paramsName = self.__asyncCmdGen.cfgCmdGen( snmpEngine, authData, transportTarget )
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
        cache = self._getCache(snmpEngine)
        if authData:
            authDataKey = authData.securityName, authData.securityModel
            if authDataKey in cache['auth']:
                authDataKeys = ( authDataKey, )
            else:
                raise error.PySnmpError('Unknown authData %s' % (authData,))
        else:
            authDataKeys = tuple(cache['auth'].keys())

        addrNames, paramsNames = self.__asyncCmdGen.uncfgCmdGen(snmpEngine, authData)

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

    def makeVarBinds(self, snmpEngine, varBinds):
        mibViewController = self.getMibViewController(snmpEngine)
        if isinstance(varBinds, NotificationType):
            varBinds.resolveWithMib(mibViewController)
        __varBinds = []
        for varBind in varBinds:
            if isinstance(varBind, ObjectType):
                pass
            elif isinstance(varBind[0], ObjectIdentity):
                varBind = ObjectType(*varBind)
            else:
                varBind = ObjectType(ObjectIdentity(varBind[0]), varBind[1])
            __varBinds.append(varBind.resolveWithMib(mibViewController))
        return __varBinds

    def unmakeVarBinds(self, snmpEngine, varBinds, lookupMib=False):
        if lookupMib:
            mibViewController = self.getMibViewController(snmpEngine)
            varBinds = [ ObjectType(ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds ]
        return varBinds

    def sendNotification(self, snmpEngine,
                         authData, transportTarget, contextData,
                         notifyType,
                         varBinds,
                         cbInfo=(None, None), 
                         lookupMib=False):

        def __cbFun(snmpEngine, sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBinds, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun and cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus, errorIndex,
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )

        cbFun, cbCtx = cbInfo

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

        return ntforg.NotificationOriginator().sendVarBinds(snmpEngine, notifyName, contextData.contextEngineId, contextData.contextName, self.makeVarBinds(snmpEngine, varBinds), __cbFun, (lookupMib, cbFun, cbCtx))

#
# The rest of code in this file belongs to obsolete, compatibility wrappers.
# Never use interfaces below for new applications!
#

# substitute sendNotification return object for backward compatibility
class ErrorIndicationReturn:
    def __init__(self, *vars): self.__vars = vars
    def __getitem__(self, i): return self.__vars[i]
    def __nonzero__(self): return self.__vars[0] and 1 or 0
    def __bool__(self): return bool(self.__vars[0])
    def __str__(self): return str(self.__vars[0])

class AsynNotificationOriginator:
    def __init__(self, snmpEngine=None, snmpContext=None):
        if snmpEngine is None:
            self.snmpEngine = snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine

        if snmpContext is None:
            self.snmpContext = context.SnmpContext(self.snmpEngine)
            config.addContext(
                self.snmpEngine, ''  # this is leaky
            )
        else:
            self.snmpContext = snmpContext

        self.__asyncNtfOrg = AsyncNotificationOriginator()

        self.mibViewController = self.__asyncNtfOrg.getMibViewController(self.snmpEngine)

    def __del__(self): self.uncfgNtfOrg()

    def cfgNtfOrg(self, authData, transportTarget, notifyType):
        return self.__asyncNtfOrg.cfgNtfOrg(
            self.snmpEngine, authData, transportTarget, notifyType
        )

    def uncfgNtfOrg(self, authData=None):
        return self.__asyncNtfOrg.uncfgNtfOrg(self.snmpEngine, authData)
        
    def makeVarBinds(self, varBinds):
        return self.__asyncNtfOrg.makeVarBinds(
            self.snmpEngine, varBinds
        )

    def unmakeVarBinds(self, varBinds, lookupNames, lookupValues):
        return self.__asyncNtfOrg.unmakeVarBinds(
            self.snmpEngine, varBinds, lookupNames or lookupValues
        )

    def sendNotification(self, authData, transportTarget, 
                         notifyType, notificationType,
                         varBinds=(),  # legacy, use NotificationType instead
                         cbInfo=(None, None),
                         lookupNames=False, lookupValues=False,
                         contextEngineId=None,  # XXX ordering incompatibility
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

        if not isinstance(notificationType,
                          (ObjectIdentity, ObjectType, NotificationType)):
            if isinstance(notificationType[0], tuple):
                # legacy
                notificationType = ObjectIdentity(notificationType[0][0], notificationType[0][1], *notificationType[1:])
            else:
                notificationType = ObjectIdentity(notificationType)

        if not isinstance(notificationType, NotificationType):
            notificationType = NotificationType(notificationType)

        return self.__asyncNtfOrg.sendNotification(
            self.snmpEngine,
            authData, transportTarget, 
            ContextData(contextEngineId or self.snmpContext.contextEngineId,
                        contextName),
            notifyType, notificationType.addVarBinds(*varBinds),
            (__cbFun, cbInfo),
            lookupNames or lookupValues
        )

    asyncSendNotification = sendNotification

class NotificationOriginator:
    def __init__(self, snmpEngine=None, snmpContext=None, asynNtfOrg=None):
        # compatibility attributes
        self.snmpEngine = snmpEngine or SnmpEngine()
        self.mibViewController = AsyncNotificationOriginator().getMibViewController(self.snmpEngine)

    # the varBinds parameter is legacy, use NotificationType instead

    def sendNotification(self, authData, transportTarget, notifyType,
                         notificationType, *varBinds, **kwargs):
        for x in sendNotification(self.snmpEngine, authData, transportTarget,
                                  ContextData(kwargs.get('contextEngineId'),
                                              kwargs.get('contextName', null)),
                                  notifyType,
                                  notificationType.addVarBinds(*varBinds),
                                  **kwargs):
            return x

# circular module import dependency 
from sys import version_info
if version_info[:2] < (2, 6):
    from pysnmp.entity.rfc3413.oneliner.sync.compat.ntforg import *
else:
    from pysnmp.entity.rfc3413.oneliner.sync.ntforg import *
