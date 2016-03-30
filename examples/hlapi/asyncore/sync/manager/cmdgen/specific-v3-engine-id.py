"""
Discover SNMPv3 SecurityEngineId
++++++++++++++++++++++++++++++++

Send SNMP GET request using the following scenario and options:

* try to communicate with a SNMPv3 Engine using:

* a non-existing user
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161

* if remote SNMP Engine ID is discovered, send SNMP GET request:

* with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
   at discovered securityEngineId
* to the same SNMP Engine ID
* for an OID in text form

"""#
from pysnmp.hlapi import *

snmpEngine = SnmpEngine()

transportTarget = UdpTransportTarget(('demo.snmplabs.com', 161))

#
# To discover remote SNMP EngineID we will tap on SNMP engine inner workings
# by setting up execution point observer setup on INTERNAL class PDU processing
#

observerContext = {}

# Register a callback to be invoked at specified execution point of 
# SNMP Engine and passed local variables at execution point's local scope
snmpEngine.observer.registerObserver(
    lambda e, p, v, c: c.update(securityEngineId=v['securityEngineId']),
    'rfc3412.prepareDataElements:internal',
    cbCtx=observerContext
)

# Send probe SNMP request with invalid credentials

authData = UsmUserData('non-existing-user')

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(snmpEngine, authData, transportTarget, ContextData(),
           ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
)

# See if our SNMP engine received REPORT PDU containing securityEngineId

if 'securityEngineId' not in observerContext:
    print("Can't discover peer EngineID, errorIndication: %s" % errorIndication)
    raise Exception()

securityEngineId = observerContext.pop('securityEngineId')

print('Remote securityEngineId = %s' % securityEngineId.prettyPrint())

#
# Query remote SNMP Engine using usmUserTable entry configured for it
#

authData = UsmUserData('usr-md5-none', 'authkey1',
                       securityEngineId=securityEngineId)

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(snmpEngine,
           authData,
           transportTarget,
           ContextData(),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for name, val in varBinds:
        print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
