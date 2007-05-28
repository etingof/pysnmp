import types
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntforg, context, mibvar
from pysnmp.entity.rfc3413.oneliner import cmdgen

# Auth protocol
usmHMACMD5AuthProtocol = cmdgen.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = cmdgen.usmHMACSHAAuthProtocol
usmNoAuthProtocol = cmdgen.usmNoAuthProtocol

# Privacy protocol
usmDESPrivProtocol = cmdgen.usmDESPrivProtocol
usmNoPrivProtocol = cmdgen.usmNoPrivProtocol

# Credentials
CommunityData = cmdgen.CommunityData
UsmUserData = cmdgen.UsmUserData

# Transport
UdpTransportTarget = cmdgen.UdpTransportTarget

class AsynNotificationOriginator(cmdgen.AsynCommandGenerator):
    def __init__(self, snmpEngine=None, snmpContext=None):
        cmdgen.AsynCommandGenerator.__init__(self, snmpEngine)
        self.snmpContext = snmpContext
        self.__knownAuths = {}

    def __del__(self): self.uncfgNtfOrg()

    def cfgNtfOrg(self, authData, transportTarget, notifyType, tagList=''):
        addrName, paramsName = self.cfgCmdGen(authData, transportTarget,
                                              tagList)
        notifyName = 'n-%s' % hash(tagList)
        if not self.__knownAuths.has_key(authData):
            config.addNotificationTarget(
                self.snmpEngine,
                notifyName,
                paramsName,
                tagList,
                notifyType
                )
            config.addContext(
                self.snmpEngine, ''  # this is leaky
                )
            subTree = (1,3,6)
            config.addTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree
                )
            if self.snmpContext is None:
                self.snmpContext = context.SnmpContext(self.snmpEngine)
            self.__knownAuths[authData] = notifyName, paramsName, subTree
        return notifyName
    
    def uncfgNtfOrg(self):
        self.uncfgCmdGen()
        for authData, (notifyName, paramsName, subTree) in self.__knownAuths.items():
            config.delNotificationTarget(
                self.snmpEngine, notifyName, paramsName
                )
            config.delTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree
                )

    def asyncSendNotification(
        self, authData, transportTarget, notifyType,
        notificationType, varBinds=None, (cbFun, cbCtx)=(None, None)
        ):
        tagList = 'notify-list'
        notifyName = self.cfgNtfOrg(authData, transportTarget,
                                    notifyType, tagList)
        if notificationType:
            name, oid = mibvar.mibNameToOid(
                self.mibViewController, notificationType
                )
            notificationType = name + oid
        if varBinds:
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
        else:
            __varBinds = None

        return ntforg.NotificationOriginator(self.snmpContext).sendNotification(self.snmpEngine, notifyName, notificationType, __varBinds, cbFun, cbCtx)

class NotificationOriginator(AsynNotificationOriginator):
    def sendNotification(
        self, authData, transportTarget, notifyType,
        notificationType, *varBinds
        ):
        def __cbFun(sendRequestHandle, errorIndication, appReturn):
            appReturn['errorIndication'] = errorIndication

        appReturn = {}
        errorIndication = self.asyncSendNotification(
            authData, transportTarget, notifyType, notificationType, varBinds,
            (__cbFun, appReturn)
            )
        if errorIndication:
            return errorIndication
        self.snmpEngine.transportDispatcher.runDispatcher()
        return appReturn.get('errorIndication')
