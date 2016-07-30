"""
INFORM notification
+++++++++++++++++++

Send SNMP INFORM notification using the following options:

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send INFORM notification
* to a Manager at 104.236.166.95:162
* with TRAP ID 'coldStart' specified as an OID
* include managed objects information:
  1.3.6.1.2.1.1.1.0 = 'Example Notificator'
  1.3.6.1.2.1.1.5.0 = 'Notificator Example'

Functionally similar to:

| $ snmpinform -v2c -c public 104.236.166.95 12345 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.1.0 s 'Example Notificator' 1.3.6.1.2.1.1.5.0 s 'Notificator Example'

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SecurityName <-> CommunityName mapping (+ transport binding)
config.addV1System(snmpEngine, 'my-area', 'public',
                   transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv2c -> 1)
config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)

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
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'inform'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (2), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (), (), (1, 3, 6))

# *** SNMP engine configuration is complete by this line ***

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator()


# Error/confirmation receiver
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    print('Notification %s, status - %s' % (
        sendRequestHandle, errorIndication and errorIndication or 'delivered'
    )
          )


# Build and submit notification message to dispatcher
sendRequestHandle = ntfOrg.sendVarBinds(
    snmpEngine,
    'my-notification',  # notification targets
    None, '',  # contextEngineId, contextName
    # var-binds
    [
        # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::coldStart
        ((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), v2c.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1))),
        # additional var-binds: ( (oid, value), ... )
        ((1, 3, 6, 1, 2, 1, 1, 1, 0), v2c.OctetString('Example Notificator')),
        ((1, 3, 6, 1, 2, 1, 1, 5, 0), v2c.OctetString('Notificator Example'))
    ],
    cbFun
)

print('Notification %s scheduled to be sent' % sendRequestHandle)

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
