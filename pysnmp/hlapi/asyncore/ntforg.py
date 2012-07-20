from pyasn1.type import base
from pysnmp import nextid
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntforg, context, mibvar
from pysnmp.entity.rfc3413.oneliner import cmdgen

# Auth protocol
usmHMACMD5AuthProtocol = cmdgen.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = cmdgen.usmHMACSHAAuthProtocol
usmNoAuthProtocol = cmdgen.usmNoAuthProtocol

# Privacy protocol
usmDESPrivProtocol = cmdgen.usmDESPrivProtocol
usm3DESEDEPrivProtocol = cmdgen.usm3DESEDEPrivProtocol
usmAesCfb128Protocol = cmdgen.usmAesCfb128Protocol
usmAesCfb192Protocol = cmdgen.usmAesCfb192Protocol
usmAesCfb256Protocol = cmdgen.usmAesCfb256Protocol
usmNoPrivProtocol = cmdgen.usmNoPrivProtocol

# Credentials
CommunityData = cmdgen.CommunityData
UsmUserData = cmdgen.UsmUserData

# Transports
UdpTransportTarget = cmdgen.UdpTransportTarget
Udp6TransportTarget = cmdgen.Udp6TransportTarget
UnixTransportTarget = cmdgen.UnixTransportTarget

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
            k = paramsName, tag, notifyType
            if k in self.__knownNotifyNames:
                notifyName, _ = self.__knownNotifyNames[k]
            else:
                notifyName = 'n%s' % nextID()
                config.addNotificationTarget(
                    self.snmpEngine,
                    notifyName,
                    paramsName,
                    tag,
                    notifyType
                )
                self.__knownNotifyNames[k] = notifyName, paramsName
        k = ( authData.securityModel,
              authData.securityName,
              authData.securityLevel )
        if k not in self.__knownAuths:
            subTree = (1,3,6)
            config.addTrapUser(
                self.snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree
                )
            self.__knownAuths[k] = subTree
        if self.snmpContext is None:
            self.snmpContext = context.SnmpContext(self.snmpEngine)
            config.addContext(
                self.snmpEngine, ''  # this is leaky
            )
        return notifyName
    
    def uncfgNtfOrg(self):
        for notifyName, paramsName in self.__knownNotifyNames.values():
            config.delNotificationTarget(
                self.snmpEngine, notifyName, paramsName
                )
        for k, subTree in self.__knownAuths.items():
            securityModel, securityName, securityLevel = k
            config.delTrapUser(
                self.snmpEngine,
                securityModel,
                securityName,
                securityLevel,
                subTree
                )
        self.uncfgCmdGen()

    def sendNotification(
        self, authData, transportTarget, notifyType,
        notificationType, varBinds=None, cbInfo=(None, None)
        ):
        (cbFun, cbCtx) = cbInfo
        notifyName = self.cfgNtfOrg(authData, transportTarget, notifyType)
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
                if not isinstance(varVal, base.Asn1ItemBase):
                    ((symName, modName), suffix) = mibvar.oidToMibName(
                        self.mibViewController, name + oid
                        )
                    syntax = mibvar.cloneFromMibValue(
                        self.mibViewController, modName, symName, varVal
                        )
                    if syntax is None:
                        raise error.PySnmpError(
                            'Value type MIB lookup failed for %r' % (varName,)
                            )
                    varVal = syntax.clone(varVal)
                __varBinds.append((name + oid, varVal))
        else:
            __varBinds = None

        return ntforg.NotificationOriginator(self.snmpContext).sendNotification(self.snmpEngine, notifyName, notificationType, __varBinds, cbFun, cbCtx)

    asyncSendNotification = sendNotification
    
class NotificationOriginator:
    def __init__(self, snmpEngine=None, snmpContext=None, asynNtfOrg=None):
        if asynNtfOrg is None:
            self.__asynNtfOrg = AsynNotificationOriginator(
                snmpEngine, snmpContext
                )
        else:
            self.__asynNtfOrg = asynNtfOrg

    def sendNotification(
        self, authData, transportTarget, notifyType,
        notificationType, *varBinds
        ):
        def __cbFun(sendRequestHandle, errorIndication, appReturn):
            appReturn['errorIndication'] = errorIndication

        # Setup transport tags if not given by user
        if not transportTarget.tagList:
            transportTarget.tagList = str(hash((authData, transportTarget)))
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        appReturn = {}
        self.__asynNtfOrg.sendNotification(
            authData, transportTarget, notifyType, notificationType, varBinds,
            (__cbFun, appReturn)
            )
        self.__asynNtfOrg.snmpEngine.transportDispatcher.runDispatcher()
        if 'errorIndication' in appReturn:
            return appReturn['errorIndication']
