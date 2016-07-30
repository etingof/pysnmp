"""
SNMPv1 TRAP
+++++++++++

Send SNMP notification using the following options:

* SNMPv1
* with community name 'public'
* over IPv4/UDP
* to a Manager at 104.236.166.95:162
* send TRAP notification
* with TRAP ID 'coldStart' specified as an OID
* include managed objects information:
* overriding Uptime value with 12345
* overriding Agent Address with '104.236.166.95'
* overriding Enterprise OID with 1.3.6.1.4.1.20408.4.1.1.2
* include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'

Functionally similar to:

| $ snmptrap -v1 -c public demo.snmplabs.com 1.3.6.1.4.1.20408.4.1.1.2 104.236.166.95 6 432 12345 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public', transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv1 -> 0)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 0)

# Setup transport endpoint and bind it with security settings yielding
# a target name
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
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
    # Notification targets
    'my-notification',  # notification targets
    None, '',  # contextEngineId, contextName
    # var-binds
    [
        # Uptime value with 12345
        (v2c.ObjectIdentifier('1.3.6.1.2.1.1.3.0'),
         v2c.TimeTicks(12345)),
        # trap OID: Generic Trap #6 (enterpriseSpecific)
        #           and Specific Trap 432
        (v2c.ObjectIdentifier('1.3.6.1.6.3.1.1.5.1'),
         v2c.ObjectIdentifier('1.3.6.1.4.1.20408.4.1.1.2.0.432')),
        # Agent Address with '127.0.0.1'
        (v2c.ObjectIdentifier('1.3.6.1.6.3.18.1.3.0'),
         v2c.IpAddress('127.0.0.1')),
        # Enterprise OID with 1.3.6.1.4.1.20408.4.1.1.2
        (v2c.ObjectIdentifier('1.3.6.1.6.3.1.1.4.3.0'),
         v2c.ObjectIdentifier('1.3.6.1.4.1.20408.4.1.1.2')),
        # managed object '1.3.6.1.2.1.1.1.0' = 'my system'
        (v2c.ObjectIdentifier('1.3.6.1.2.1.1.1.0'),
         v2c.OctetString('my system'))
    ]
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and stop
snmpEngine.transportDispatcher.runDispatcher()
