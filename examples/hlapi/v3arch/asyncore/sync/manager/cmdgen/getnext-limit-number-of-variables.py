"""
Fetch fixed amount of MIB variables
+++++++++++++++++++++++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv3, user 'usr-sha-aes128', SHA auth, AES128 privacy
* over UDP/IPv4
* to an Agent at demo.snmplabs.com:161
* for all OIDs past SNMPv2-MIB
* run till end-of-mib condition is reported by Agent OR maxRows == 100
* ignoring non-increasing OIDs whenever reported by Agent

Functionally similar to:

| $ snmpwalk -v3 -lauthPriv -u usr-sha-aes128 -A authkey1 -X privkey1 -a MD5 -x AES  demo.snmplabs.com SNMPv2-MIB::system

"""#
from pysnmp.hlapi import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in nextCmd(SnmpEngine(),
                          UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                                      authProtocol=usmHMACSHAAuthProtocol,
                                      privProtocol=usmAesCfb128Protocol),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('SNMPv2-MIB')),
                          maxRows=100, ignoreNonIncreasingOid=True):

    if errorIndication:
        print(errorIndication)
        break
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
