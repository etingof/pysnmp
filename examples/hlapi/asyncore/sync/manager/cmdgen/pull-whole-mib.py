#
# Command Generator
#
# Send SNMP GETNEXT requests using the following options:
#
# * with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for all OIDs in IF-MIB
# * stop when response OIDs leave the scopes of the table
# * perform response values resolution at MIB
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        UsmUserData('usr-md5-none', 'authkey1'),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('IF-MIB', '')),
                        lookupValues=True):
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
