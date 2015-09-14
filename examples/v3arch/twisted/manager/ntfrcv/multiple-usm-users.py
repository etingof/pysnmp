"""
Multiple SNMP USM users
+++++++++++++++++++++++

Receive SNMP TRAP/INFORM messages with the following options:

* SNMPv3
* with USM users:
    * 'usr-md5-des', auth: MD5, priv DES, ContextEngineId: 8000000001020304
    * 'usr-md5-none', auth: MD5, priv NONE, ContextEngineId: 8000000001020304
    * 'usr-sha-aes128', auth: SHA, priv AES, ContextEngineId: 8000000001020304
* over IPv4/UDP, listening at 127.0.0.1:162
* using Twisted framework for network transport
* print received data on stdout

Either of the following Net-SNMP commands will send notifications to this
receiver:

| $ snmptrap -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 -e 8000000001020304 127.0.0.1 123 1.3.6.1.6.3.1.1.5.1
| $ snmptrap -v3 -u usr-md5-none -l authNoPriv -A authkey1 -e 8000000001020304 127.0.0.1 123 1.3.6.1.6.3.1.1.5.1
| $ snmpinform -v3 -u usr-sha-aes128 -l authPriv -a SHA -A authkey1 -x AES -X privkey1 127.0.0.1 123 1.3.6.1.6.3.1.1.5.1

"""#
from twisted.internet import reactor
from pysnmp.entity import engine, config
from pysnmp.carrier.twisted.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto import rfc1902

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTwistedTransport().openServerMode(('127.0.0.1', 162))
)

# -- begin of SNMPv3/USM setup

# user: usr-md5-des, auth: MD5, priv DES
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1'
)

# user: usr-md5-des, auth: MD5, priv DES, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-md5-des',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    config.usmDESPrivProtocol, 'privkey1',
    securityEngineId=rfc1902.OctetString(hexValue='8000000001020304')
)

# user: usr-md5-none, auth: MD5, priv NONE
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)

# user: usr-md5-none, auth: MD5, priv NONE, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1',
    securityEngineId=rfc1902.OctetString(hexValue='8000000001020304')
)

# user: usr-sha-aes128, auth: SHA, priv AES
config.addV3User(
    snmpEngine, 'usr-sha-aes128',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1'
)

# user: usr-sha-aes128, auth: SHA, priv AES, securityEngineId: 8000000001020304
# this USM entry is used for TRAP receiving purposes
config.addV3User(
    snmpEngine, 'usr-sha-aes128',
    config.usmHMACSHAAuthProtocol, 'authkey1',
    config.usmAesCfb128Protocol, 'privkey1',
    securityEngineId=rfc1902.OctetString(hexValue='8000000001020304')
)

# -- end of SNMPv3/USM setup

# Callback function for receiving notifications
def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    print('Notification from ContextEngineId "%s", ContextName "%s"' % (
            contextEngineId.prettyPrint(), contextName.prettyPrint()
        )
    )
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
 
# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmpEngine, cbFun)

# Run Twisted main loop
reactor.run()
