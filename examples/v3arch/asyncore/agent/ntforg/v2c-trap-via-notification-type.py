#
# Notification Originator
#
# Send SNMP TRAP notification using the following options:
#
# * SNMPv2c
# * with community name 'public'
# * over IPv4/UDP
# * send TRAP notification
# * to a Manager at 127.0.0.1:162
# * with TRAP ID ACCOUNTING-CONTROL-MIB::acctngFileFull as MIB symbol
#
# The ACCOUNTING-CONTROL-MIB::acctngFileFull NOTIFICATION-TYPE implies
# including three other var-binds into the TRAP describing the incident
# occurred. These var-binds are: 
# ACCOUNTING-CONTROL-MIB::acctngFileMaximumSize.0
# ACCOUNTING-CONTROL-MIB::acctngFileNameSuffix.0
# ACCOUNTING-CONTROL-MIB::acctngFileName.0
#
# To run this example make sure to have ACCOUNTING-CONTROL-MIB.py in
# search path.
#
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.proto.api import v2c

# Create SNMP engine instance
snmpEngine = engine.SnmpEngine()

# Create default SNMP context where contextEngineId == SnmpEngineId
snmpContext = context.SnmpContext(snmpEngine)

#
# Here we fill in some values for Managed Objects Instances (invoked
# later while building TRAP message) by NOTIFICATION-TYPE macro evaluation.
# In real Agent app, these values should already be initialized during
# Agent runtime.
#

mibInstrumCtl = snmpContext.getMibInstrum('')
( MibScalarInstance, ) = mibInstrumCtl.mibBuilder.importSymbols(
                             'SNMPv2-SMI',
                             'MibScalarInstance'
                         )
( acctngFileFull,
  acctngFileMaximumSize,
  acctngFileNameSuffix,
  acctngFileName ) = mibInstrumCtl.mibBuilder.importSymbols(
                         'ACCOUNTING-CONTROL-MIB',
                         'acctngFileFull',
                         'acctngFileMaximumSize',
                         'acctngFileNameSuffix',
                         'acctngFileName'
                     )

mibInstrumCtl.mibBuilder.exportSymbols(
  '__ACCOUNTING-CONTROL-MIB',
  MibScalarInstance(acctngFileMaximumSize.name, (0,), acctngFileMaximumSize.syntax.clone(123)),
  MibScalarInstance(acctngFileNameSuffix.name, (0,), acctngFileNameSuffix.syntax.clone('.log')),
  MibScalarInstance(acctngFileName.name, (0,), acctngFileName.syntax.clone('mylogfile')),
)

#
# End of Agent's Managed Object Instances initialization
#

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
ntfOrg = ntforg.NotificationOriginator(snmpContext)
 
# Build and submit notification message to dispatcher
ntfOrg.sendNotification(
    snmpEngine,
    # Notification targets
    'my-notification',
    # Trap type
    ('ACCOUNTING-CONTROL-MIB', 'acctngFileFull'),
    # MIB scalar/table instances of NOTIFICATION-TYPE objects
    instanceIndex=(0,)
)

print('Notification is scheduled to be sent')

# Run I/O dispatcher which would send pending message and process response
snmpEngine.transportDispatcher.runDispatcher()
