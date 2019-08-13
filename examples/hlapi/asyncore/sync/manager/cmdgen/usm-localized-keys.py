"""
SNMPv3: localized auth and privacy keys
+++++++++++++++++++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3, user 'usr-md5-des', MD5 authentication, DES encryption
* use localized auth and privacy keys instead of pass-phrase or master keys
* configure authoritative SNMP engine ID (0x0000000000 can be used as well)
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for SNMPv2-MIB::sysDescr.0 MIB object instance

Functionally similar to:

| $ snmpget -v3 -l authPriv \
      -u usr-md5-des \
      -e 0x80004fb805636c6f75644dab22cc \
      -3k 0x6b99c475259ef7976cf8d028a3381eeb \
      -3K 0x92b5ef98f0a216885e73944e58c07345 \
      demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           UsmUserData('usr-md5-des',
                       authKey=OctetString(
                           hexValue='6b99c475259ef7976cf8d028a3381eeb'),
                       privKey=OctetString(
                           hexValue='92b5ef98f0a216885e73944e58c07345'),
                       authKeyType=usmKeyTypeLocalized,
                       privKeyType=usmKeyTypeLocalized,
                       securityEngineId=OctetString(
                           hexValue='80004fb805636c6f75644dab22cc')),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
