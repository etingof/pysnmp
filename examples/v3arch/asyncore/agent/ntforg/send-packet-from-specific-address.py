"""
Send packet from specific network interface/port
++++++++++++++++++++++++++++++++++++++++++++++++

Send SNMP notification using the following options:

* SNMPv1
* with community name 'public'
* over IPv4/UDP
* to a Manager at 104.236.166.95 UDP port 162
* from local address 0.0.0.0, UDP port 61024
* send TRAP notification
* with TRAP ID 'coldStart' specified as an OID

Functionally similar to:

| $ snmptrap -v1 -c public 104.236.166.95 1.3.6.1.6.3.1.1.5.1 0.0.0.0 1 0 0

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public',
                   transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv1 -> 0)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 0)

# Setup transport endpoint and bind it with security settings yielding
# a target name. Pay attention to the openClientMode() parameter -- it's
# used to originate packets from particular local IP:port
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode(iface=('0.0.0.0', 61024))
)
config.addTargetAddr(
    snmpEngine, 'my-nms',
    udp.domainName, ('104.236.166.95', 162),
    'my-creds',
    tagList='all-my-managers'
)

# Specify what kind of notification should be sent (TRAP or INFORM),
# to what targets (chosen by tag) and what filter should apply to
# the set of targets (selected by tag)
config.addNotificationTarget(
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'trap'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (1), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 1, 'my-area', 'noAuthNoPriv', (), (), (1, 3, 6))

# *** SNMP engine configuration is complete by this line ***

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator()

# Build and submit notification message to dispatcher
ntfOrg.sendVarBinds(
    snmpEngine,
    'my-notification',  # notification targets
    None, '',  # contextEngineId, contextName
    # var-binds
    [
        # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::coldStart
        ((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), v2c.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))
    ]
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and stop
snmpEngine.transportDispatcher.runDispatcher()
