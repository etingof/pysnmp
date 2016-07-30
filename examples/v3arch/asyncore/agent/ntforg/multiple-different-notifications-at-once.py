"""
Notification over multiple SNMP versions
++++++++++++++++++++++++++++++++++++++++

Send SNMP INFORM notifications to multiple Managers using different
security settings:

* SNMPv2c
* with community name 'public'
* AND
* SNMPv3
* with user 'usr-md5-none', auth: MD5, priv NONE
* over IPv4/UDP
* send INFORM notification
* to multiple Managers at 104.236.166.95:162, 104.236.166.95:162
* with TRAP ID 'coldStart' specified as an OID
* include managed objects information:
  1.3.6.1.2.1.1.1.0 = 'Example Notificator'

Functionally similar to:

| $ snmpinform -v3 -l authPriv -u usr-md5-none -A authkey1 104.236.166.95 0 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.1.0 s 'Example notification'
| $ snmpinform -v2c -c public 104.236.166.95 0 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.1.0 s 'Example notification'

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# SNMPv2c:

# SecurityName <-> CommunityName mapping
config.addV1System(snmpEngine, 'my-area', 'public', transportTag='all-my-managers')

# Specify security settings per SecurityName (SNMPv2c -> 1)
config.addTargetParams(snmpEngine, 'my-creds-1', 'my-area', 'noAuthNoPriv', 1)

# SNMPv3:

config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)
config.addTargetParams(snmpEngine, 'my-creds-2', 'usr-md5-none', 'authNoPriv')

# Setup transport endpoint and bind it with security settings yielding
# a target name
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpSocketTransport().openClientMode()
)
# First target
config.addTargetAddr(
    snmpEngine, 'my-nms-1',
    udp.domainName, ('104.236.166.95', 162),
    'my-creds-1',
    tagList='all-my-managers'
)
# Second target
config.addTargetAddr(
    snmpEngine, 'my-nms-2',
    udp.domainName, ('104.236.166.95', 162),
    'my-creds-2',
    tagList='all-my-managers'
)

# Specify what kind of notification should be sent (TRAP or INFORM),
# to what targets (chosen by tag) and what filter should apply to
# the set of targets (selected by tag)
config.addNotificationTarget(
    snmpEngine, 'my-notification', 'my-filter', 'all-my-managers', 'inform'
)

# Allow NOTIFY access to Agent's MIB by this SNMP model (2&3), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (), (), (1, 3, 6))
config.addVacmUser(snmpEngine, 3, 'usr-md5-none', 'authNoPriv', (), (), (1, 3, 6))

# *** SNMP engine configuration is complete by this line ***

# Create Notification Originator App instance. 
ntfOrg = ntforg.NotificationOriginator()


# Error/confirmation receiver
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    print('Notification %s, status - %s' % (sendRequestHandle,
                                            errorIndication and errorIndication or 'delivered'))


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
        ((1, 3, 6, 1, 2, 1, 1, 1, 0), v2c.OctetString('Example Notificator'))
    ],
    cbFun
)

print('Notifications %s are scheduled to be sent' % sendRequestHandle)

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
