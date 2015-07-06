#
# Command Generator
#
# Send SNMP GETNEXT request using the following options:
#
# * with SNMPv1, community 'public'
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for some columns of the IF-MIB::ifEntry table
# * stop when response OIDs leave the scopes of initial OIDs
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        CommunityData('public', mpModel=0),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifDescr')),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifType')),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifMtu')),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifSpeed')),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifPhysAddress')),
                        ObjectType(ObjectIdentity('IF-MIB', 'ifType'))):
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
