"""
Custom ContextEngineId
++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
* use remote SNMP Engine ID 0x80004fb805636c6f75644dab22cc (USM
  autodiscovery will run)
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* setting SNMPv2-MIB::sysName.0 to new value (type coerced from MIB)

Functionally similar to:

| $ snmpset -v3 -u usr-md5-des -l authPriv -A authkey1 -X privkey1 -E 80004fb805636c6f75644dab22cc demo.snmplabs.com SNMPv2-MIB::sysORDescr.1 = "new system name"

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    setCmd(SnmpEngine(),
           UsmUserData('usr-md5-des', 'authkey1', 'privkey1',
                       securityEngineId=OctetString(hexValue='80004fb805636c6f75644dab22cc')),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0), 'new system name'))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
