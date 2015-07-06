#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
# * over IPv6/UDP
# * to an Agent at [::1]:161
# * for three OIDs: one passed as a ObjectIdentity object while others are
# * in string form
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in getCmd(SnmpEngine(),
                       UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                       Udp6TransportTarget(('::1', 161)),
                       ContextData(),
                       ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
                       ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')),
                       ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))
    break
