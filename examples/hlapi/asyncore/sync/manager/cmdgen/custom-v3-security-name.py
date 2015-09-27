"""
Custom SecurityName
+++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv3, user 'usr-md5-none', securityName 'myuser'
  MD5 authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for an OID in text form

The securityName parameter can be thought as an alias to userName and
allows you to address a USM Table row just as userName does. However
securityName can be made human-readable, also it is not an index in
usmUserTable, thus duplicate securityName parameters are possible.
"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           UsmUserData('usr-md5-none', 'authkey1', securityName='myuser'),
           UdpTransportTarget(('demo.snmplabs.com', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
)

if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
        )
    )
else:
    for varBind in varBinds:
        print(' = '.join([ x.prettyPrint() for x in varBind ]))
