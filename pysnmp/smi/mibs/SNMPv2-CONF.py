
( MibNodeBase,
  NotificationType ) = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibNodeBase',
    'NotificationType'
    )

class ObjectGroup(NotificationType): pass
class NotificationGroup(NotificationType): pass
class ModuleCompliance(MibNodeBase): pass
class AgentCapabilities(MibNodeBase): pass

mibBuilder.exportSymbols(
    'SNMPv2-CONF',
    ObjectGroup=ObjectGroup,
    NotificationGroup=NotificationGroup,
    ModuleCompliance=ModuleCompliance,
    AgentCapabilities=AgentCapabilities
    )

