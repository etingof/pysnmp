#
# Command Generator
#
# Send SNMP GETNEXT requests using the following options:
#
# * with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
# * over IPv6/UDP
# * to an Agent at [::1]:161
# * for all columns of the IF-MIB::ifEntry table
# * stop when response OIDs leave the scopes of the table
# * perform response OIDs and values resolution at MIB
#
# make sure IF-MIB.py is in search path
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
                        Udp6TransportTarget(('::1', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifEntry')),
                        lookupNames=True, lookupValues=True):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
        break
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
            break
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))
