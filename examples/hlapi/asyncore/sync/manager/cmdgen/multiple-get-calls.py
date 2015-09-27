"""
Sequence Of GET's
+++++++++++++++++

Send two SNMP GET requests in a row using the following options:

* with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for IF-MIB::ifInOctets.1 and IF-MIB::ifOutOctets.1 MIB objects

Use a queue of MIB objects to query.

The next() call is used to forward Python iterator to the position where it
could consume input

Functionally similar to:

| $ snmpget -v3 -l authNoPriv -u usr-md5-none -A authkey1 demo.snmplabs.com \
|        IF-MIB::ifInOctets.1

"""#
from pysnmp.hlapi import *

queue = [ [ ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1)) ],
          [ ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets', 1)) ] ]

iter = getCmd(SnmpEngine(),
              UsmUserData('usr-md5-none', 'authkey1'),
              UdpTransportTarget(('demo.snmplabs.com', 161)),
              ContextData())

next(iter)

while queue:
    errorIndication, errorStatus, errorIndex, varBinds = iter.send(queue.pop())
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
