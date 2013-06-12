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

class AsynNotificationOriginator(cmdgen.AsynCommandGenerator):
    def __init__(self, snmpEngine=None, snmpContext=None):
        cmdgen.AsynCommandGenerator.__init__(self, snmpEngine)
        self.snmpContext = snmpContext
        self.__knownNotifyNames = {}
        self.__knownAuths = {}

    def __del__(self): self.uncfgNtfOrg()

    def cfgNtfOrg(self, authData, transportTarget, notifyType):
        addrName, paramsName = self.cfgCmdGen(authData, transportTarget)
        tagList = transportTarget.tagList.split()
        if not tagList:
            tagList = ['']
        for tag in tagList:
            notifyNameKey = paramsName, tag, notifyType
            if notifyNameKey in self.__knownNotifyNames:
                notifyName, paramsName, useCount = self.__knownNotifyNames[notifyNameKey]
                self.__knownNotifyNames[notifyNameKey] = notifyName, paramsName, useCount + 1
            else:
                notifyName = 'n%s' % nextID()
                config.addNotificationTarget(
                    self.snmpEngine,
                    notifyName,
                    paramsName,
                    tag,
                    notifyType
                )
                self.__knownNotifyNames[notifyNameKey] = notifyName, paramsName, 1
        authDataKey = authData.securityName, authData.securityModel
        if  authDataKey in self.__knownAuths:
            authDataX, subTree, useCount = self.__knownAuths[authDataKey]
            self.__knownAuths[authDataKey] = authDataX, subTree, useCount + 1
        else:
            subTree = (1,3,6)
            config.addTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree
            )
            self.__knownAuths[authDataKey] = authData, subTree, 1
        if self.snmpContext is None:
            self.snmpContext = context.SnmpContext(self.snmpEngine)
            config.addContext(
                self.snmpEngine, ''  # this is leaky
            )
        return notifyName
    
    def uncfgNtfOrg(self, authData=None):
        if authData:
            authDataKey = authData.securityName, authData.securityModel
            if authDataKey in self.__knownAuths:
                authDataKeys = ( authDataKey, )
            else:
                raise error.PySnmpError('Unknown authData %s' % (authData,))
        else:
            authDataKeys = self.__knownAuths.keys()

        addrNames, paramsNames = self.uncfgCmdGen(authData)

        notifyAndParamsNames = [ (self.__knownNotifyNames[x], x) for x in self.__knownNotifyNames.keys() if x[0] in paramsNames ]

        for (notifyName, paramsName, useCount), notifyNameKey in notifyAndParamsNames:
            useCount -= 1
            if useCount:
                self.__knownNotifyNames[notifyNameKey] = notifyName, paramsName, useCount
            else:
                config.delNotificationTarget(
                    self.snmpEngine, notifyName, paramsName
                )
                del self.__knownNotifyNames[notifyNameKey]

        for authDataKey in authDataKeys:
            authDataX, subTree, useCount = self.__knownAuths[authDataKey]
            useCount -= 1
            if useCount:
                self.__knownAuths[authDataKey] = authDataX, subTree, useCount
            else:
                config.delTrapUser(
                    self.snmpEngine,
                    authDataX.securityModel,
                    authDataX.securityName,
                    authDataX.securityLevel,
                    subTree
                )
                del self.__knownAuths[authDataKey]

    def sendNotification(self, authData, transportTarget, notifyType,
                         notificationType, varBinds=(),
                         cbInfo=(None, None), 
                         lookupNames=False, lookupValues=False,
                         contextName=null):
        def __cbFun(sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBinds, cbCtx):
            lookupNames, lookupValues, cbFun, cbCtx = cbCtx
            if cbFun is None: # user callback not supplied
                return
            try:
                # we need to pass response PDU information to user for INFORMs
                return cbFun(
                    sendRequestHandle,
                    errorIndication,
                    errorStatus, errorIndex,
                    self.unmakeVarBinds(varBinds, lookupNames, lookupValues),
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
 
        (cbFun, cbCtx) = cbInfo

        # Create matching transport tags if not given by user
        if not transportTarget.tagList:
            transportTarget.tagList = str(hash((authData.securityName,
                                                transportTarget.transportAddr)))
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        notifyName = self.cfgNtfOrg(authData, transportTarget, notifyType)
        if isinstance(notificationType, MibVariable):
            notificationType = notificationType.resolveWithMib(self.mibViewController, oidOnly=True)
        elif isinstance(notificationType[0], tuple):  # legacy
            notificationType = MibVariable(notificationType[0][0], notificationType[0][1], *notificationType[1:]).resolveWithMib(self.mibViewController)

        return ntforg.NotificationOriginator(self.snmpContext).sendNotification(self.snmpEngine, notifyName, notificationType, self.makeVarBinds(varBinds), __cbFun, (lookupNames, lookupValues, cbFun, cbCtx), contextName)

    asyncSendNotification = sendNotification
  
# substitute sendNotification return object for backward compatibility
class ErrorIndicationReturn:
    def __init__(self, *vars): self.__vars = vars
    def __getitem__(self, i): return self.__vars[i]
    def __nonzero__(self): return self.__vars[0] and 1 or 0
    def __bool__(self): return bool(self.__vars[0])
    def __str__(self): return str(self.__vars[0])

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
