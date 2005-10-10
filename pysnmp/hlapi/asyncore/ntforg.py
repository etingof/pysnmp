from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntforg, context
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
        
    def asyncSendNotification(
        self, authData, transportTarget, notificationType, varBinds=None
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
                tagList
                )
            config.addContext(
                self.snmpEngine, ''
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
            self.__knownAuths[authData] = 1
        
        if varBinds:
            __varBinds = []
            for varName, varVal in varBinds:
                name, oid = mibvar.mibNameToOid(
                    self.mibViewController, varName
                    )
                __varBinds.append((name + oid, varVal))
        else:
            __varBinds = None
            
        return ntforg.NotificationOriginator(snmpContext).sendNotification(
            self.snmpEngine, notifyName, notificationType, __varBinds
            )

class NotificationOriginator(AsynNotificationOriginator):
    def sendNotification(
        self, authData, transportTarget, notificationType, varBinds=None
        ):
        errorIndication = self.asyncSendNotification(
            authData, transportTarget, notificationType, varBinds
            )
        if errorIndication:
            return errorIndication
        self.snmpEngine.transportDispatcher.runDispatcher()
        
