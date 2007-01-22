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

    def flushConfig(self):
        cmdgen.AsynCommandGenerator.flushConfig(self)
        for authData, (notifyName, paramsName) in self.__knownAuths.items():
            config.delNotificationTarget(
                self.snmpEngine, notifyName, paramsName
                )
            config.delTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                (1,3,6)
                )

    def asyncSendNotification(
        self, authData, transportTarget, notifyType,
        notificationType, varBinds=None, (cbFun, cbCtx)=(None, None)
        ):
        tagList = 'notify-list'
        addrName, paramsName = cmdgen.AsynCommandGenerator._configure(
            self, authData, transportTarget, tagList
            )
        
        notifyName = '%s-name' % tagList
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
            config.addTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                (1,3,6)
                )
            if self.snmpContext is None:
                self.snmpContext = context.SnmpContext(self.snmpEngine)
            self.__knownAuths[authData] = notifyName, paramsName
        
        if varBinds:
            __varBinds = []
            for varName, varVal in varBinds:
                name, oid = mibvar.mibNameToOid(
                    self.mibViewController, varName
                    )
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
