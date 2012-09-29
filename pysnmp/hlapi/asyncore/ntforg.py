from pyasn1.type import base
from pysnmp import nextid
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
        notificationType=None, varBinds=None, cbInfo=(None, None)
        ):
        (cbFun, cbCtx) = cbInfo

        # Create matching transport tags if not given by user
        if not transportTarget.tagList:
            transportTarget.tagList = str(hash((authData.securityName,
                                                transportTarget.transportAddr)))
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        notifyName = self.cfgNtfOrg(authData, transportTarget, notifyType)
        if notificationType is not None:
            if isinstance(notificationType, MibVariable):
                notificationType = notificationType.resolveWithMib(self.mibViewController, oidOnly=True)
            elif isinstance(notificationType[0], tuple):  # legacy
                notificationType = MibVariable(notificationType[0][0], notificationType[0][1], *notificationType[1:]).resolveWithMib(self.mibViewController)
        additionalVarBinds = []
        for varName, varVal in varBinds:
            if isinstance(varName, MibVariable):
                varName.resolveWithMib(self.mibViewController)
                if not isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varVal = varName.getMibNode().getSyntax().clone(varVal)
            elif isinstance(varName[0], tuple):  # legacy
                varName = MibVariable(varName[0][0], varName[0][1], *varName[1:]).resolveWithMib(self.mibViewController)
                if not isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varVal = varName.getMibNode().getSyntax().clone(varVal)
            else:
                if isinstance(varVal, base.AbstractSimpleAsn1Item):
                    varName = MibVariable(varName).resolveWithMib(self.mibViewController, oidOnly=True)
                else:
                    varName = MibVariable(varName).resolveWithMib(self.mibViewController)
                    varVal = varName.getMibNode().getSyntax().clone(varVal)
                    
            additionalVarBinds.append((varName, varVal))

        return ntforg.NotificationOriginator(self.snmpContext).sendNotification(self.snmpEngine, notifyName, notificationType, additionalVarBinds, cbFun, cbCtx)

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

        appReturn = {}
        self.__asynNtfOrg.sendNotification(
            authData, transportTarget, notifyType, notificationType, varBinds,
            (__cbFun, appReturn)
            )
        self.__asynNtfOrg.snmpEngine.transportDispatcher.runDispatcher()
        if 'errorIndication' in appReturn:
            return appReturn['errorIndication']
