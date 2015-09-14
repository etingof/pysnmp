"""
Sending notification with OBJECT's
++++++++++++++++++++++++++++++++++

Send SNMP TRAP notification using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* to a Manager at 127.0.0.1:162
* with TRAP ID IF-MIB::ifLink as MIB symbol

The IF-MIB::ifLink NOTIFICATION-TYPE implies including four other
var-binds into the notification message describing the incident
occurred. These var-binds are:
IF-MIB::ifIndex."x"
IF-MIB::ifAdminStatus."x"
IF-MIB::ifOperStatus."x"
IF-MIB::ifDescr."x"

Where "x" is MIB table index (instance index).

Functionally similar to:

| $ snmptrap -v2c -c public 127.0.0.1 0 1.3.6.1.6.3.1.1.5.3 IF-MIB::ifIndex."1" IF-MIB::ifAdminStatus."1" IF-MIB::ifOperStatus."1" IF-MIB::ifDescr."1"

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.smi import rfc1902, view

#
# Here we fill in some values for Managed Objects Instances (invoked
# later while building TRAP message) by NOTIFICATION-TYPE macro evaluation.
# In real Agent app, these values should already be initialized during
# Agent runtime.
#
instanceIndex = (1,)
objects = {
    ('IF-MIB', 'ifIndex'): instanceIndex[0],
    ('IF-MIB', 'ifAdminStatus'): 'up',
    ('IF-MIB', 'ifOperStatus'): 'down',
    ('IF-MIB', 'ifDescr'): 'eth0'
}

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# MIB view controller is used for MIB lookup purposes
mibViewController = view.MibViewController(snmpEngine.getMibBuilder())

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public', transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv2c -> 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

# Setup transport endpoints and bind it with security settings yielding
# a target name:

# UDP/IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
config.addTargetAddr(
    snmpEngine, 'my-nms-1',
    udp.domainName, ('127.0.0.1', 162),
    'my-creds',
    tagList='all-my-managers'
)

# Specify what kind of notification should be sent (TRAP or INFORM),
# to what targets (chosen by tag) and what filter should apply to
# the set of targets (selected by tag)
config.addNotificationTarget(
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'trap'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (2), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (), (), (1,3,6))

# *** SNMP engine configuration is complete by this line ***

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator()

# Build and submit notification message to dispatcher
ntfOrg.sendVarBinds(
    snmpEngine,
    'my-notification',  # notification targets
    None, '',           # contextEngineId, contextName
    rfc1902.NotificationType(
        rfc1902.ObjectIdentity('IF-MIB', 'linkUp'),
        instanceIndex=instanceIndex,
        objects=objects
    ).resolveWithMib(mibViewController)
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
