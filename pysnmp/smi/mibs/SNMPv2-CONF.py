
( MibNode, NotificationType ) = mibBuilder.importSymbols('SNMPv2-SMI','MibNode','NotificationType')

class ObjectGroup(NotificationType): pass
class NotificationGroup(NotificationType): pass
class ModuleCompliance(MibNode): pass
class AgentCapabilities(MibNode): pass

mibBuilder.exportSymbols('SNMPv2-CONF', ObjectGroup=ObjectGroup, NotificationGroup=NotificationGroup, ModuleCompliance=ModuleCompliance, AgentCapabilities=AgentCapabilities)

