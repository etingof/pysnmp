"""
SNMPv3 TRAP, auth: MD5, privacy: DES
++++++++++++++++++++++++++++++++++++

Send SNMP TRAP notification using the following options:

* SNMPv3
* with user 'usr-md5-des', auth: MD5, priv DES
* over IPv4/UDP
* send TRAP notification
* to a Manager at 104.236.166.95:162
* with TRAP ID 'warmStart' specified as an OID
* include managed object information 1.3.6.1.2.1.1.5.0 = 'system name'

Functionally similar to:

| $ snmptrap -v3 -l authPriv -u usr-md5-des -A authkey1 -X privkey1 -e 8000000001020304 demo.snmplabs.com 0 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v2c

# Create SNMP engine instance with specific (and locally unique)
# SnmpEngineId -- it must also be known to the receiving party
# and configured at its VACM users table.
snmpEngine = engine.SnmpEngine(
    snmpEngineID=v2c.OctetString(hexValue='8000000001020304')
)

# Add USM user
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
)
config.addTargetParams(snmpEngine, 'my-creds', 'usr-md5-des', 'authPriv')

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

# Allow NOTIFY access to Agent's MIB by this SNMP model (3), securityLevel
# and SecurityName
config.addContext(snmpEngine, '')
config.addVacmUser(snmpEngine, 3, 'usr-md5-des', 'authPriv', (), (), (1, 3, 6))

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
        # SNMPv2-SMI::snmpTrapOID.0 = SNMPv2-MIB::coldStart
        ((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), v2c.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1))),
        # additional var-binds: ( (oid, value), ... )
        ((1, 3, 6, 1, 2, 1, 1, 5, 0), v2c.OctetString('Notificator Example'))
    ]
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
