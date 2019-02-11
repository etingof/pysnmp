"""
SNMPv3: auth SHA, privacy AES128
++++++++++++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3, user 'usr-sha-aes', SHA authentication, AES128 encryption
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for SNMPv2-MIB::sysDescr.0 MIB object

Available authentication protocols:

#. USM_AUTH_HMAC96_MD5
#. USM_AUTH_HMAC96_SHA
#. USM_AUTH_HMAC128_SHA224
#. USM_AUTH_HMAC192_SHA256
#. USM_AUTH_HMAC256_SHA384
#. USM_AUTH_HMAC384_SHA512
#. USM_AUTH_NONE

Available privacy protocols:

#. USM_PRIV_CBC56_DES
#. USM_PRIV_CBC168_3DES
#. USM_PRIV_CFB128_AES
#. USM_PRIV_CFB192_AES
#. USM_PRIV_CFB256_AES
#. USM_PRIV_NONE

Functionally similar to:

| $ snmpget -v3 -l authPriv -u usr-sha-aes -A authkey1 -X privkey1 -a SHA -x AES demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from pysnmp.hlapi import *

iterator = getCmd(
    SnmpEngine(),
    UsmUserData('usr-sha-aes', 'authkey1', 'privkey1',
                authProtocol=USM_AUTH_HMAC96_SHA,
                privProtocol=USM_PRIV_CFB128_AES),
    UdpTransportTarget(('demo.snmplabs.com', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print(errorIndication)

elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))
