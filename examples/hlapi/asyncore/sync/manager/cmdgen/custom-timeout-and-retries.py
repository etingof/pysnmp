"""
Custom request timeout
++++++++++++++++++++++

Send SNMP GET request using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for an OID in string form 
* use custom timeout and request retries values

Transport timing settings (maximum number of request retries and 
individual request timeout in seconds) can be set on a per-target basis
as explained by the code that follows.

Keep in mind that while timeout value can be specified in fractions of a
second, default pysnmp timer resolution is quite low (about 0.5 sec)
so there's no much point in using timeouts which is not a multiple of 0.5
Internal timer can be programmatically adjusted to finer resolution if needed.

If retries value is set to 0, pysnmp will issue a single request. Even
if no response arrives, there will be no retry. Likewise, retries=1
means one initial request plus one retry.

Functionally similar to:

| $ snmpget -v1 -c public -t 2 -r 0 demo.snmplabs.com 1.3.6.1.2.1.1.1.0

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           CommunityData('public'),
           UdpTransportTarget(
               ('demo.snmplabs.com', 161), timeout=2.0, retries=0
           ),
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
