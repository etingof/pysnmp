"""
SNMPv3: master auth and privacy keys
++++++++++++++++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3, user 'usr-md5-des', MD5 authentication, DES encryption
* use master auth and privacy keys instead of pass-phrase
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for SNMPv2-MIB::sysDescr.0 MIB object instance

Functionally similar to:

| $ snmpget -v3 -l authPriv \
      -u usr-md5-des \
      -3m 0x1dcf59e86553b3afa5d32fd5d61bf0cf \
      -3M 0xec5ab55e93e1d85cb6846d0f23e845e0 \
      demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           UsmUserData('usr-md5-des',
                       authKey=OctetString(
                           hexValue='1dcf59e86553b3afa5d32fd5d61bf0cf'),
                       privKey=OctetString(
                           hexValue='ec5ab55e93e1d85cb6846d0f23e845e0'),
                       authKeyType=usmKeyTypeMaster,
                       privKeyType=usmKeyTypeMaster),
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
